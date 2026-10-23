package main

import (
	"github.com/winezer0/decipher/internal/algo"
	"github.com/winezer0/decipher/internal/cracker"
	"errors"
	"fmt"
	logging "github.com/winezer0/zaplogs"
	"io"
	"os"
)

func dictAddAction(engine *cracker.Engine, opts *Options) (err error) {
	temps := tempFiles{remove: opts.RemoveTemp}
	defer temps.cleanup(&err)
	// 将用户输入的字典文件格式进行转换 最终实现只输入文件格式
	plainFiles, plainTemp, err := temps.resolve(opts.UsedPlains, engine.RunCacheDir, "add_plain")
	if err != nil {
		return err
	}
	logging.Infof("choices plain files: %s, temp: %s", plainFiles, plainTemp)

	// 当用户没有指定有效密钥字典时，将密钥字典设置设置为空
	secretFiles, _, err := temps.resolve(opts.UsedSecrets, engine.RunCacheDir, "add_secret")
	if err != nil {
		return err
	}
	if len(secretFiles) == 0 {
		secretFiles = []string{}
		logging.Infof("use empty secret dicts: %v", secretFiles)
	}

	// 仅追加用户提供的字典，不触发预计算。
	builtinPlain := engine.GetBuiltinPlainPath()
	builtinSalt := engine.GetBuiltinSaltPath()

	// 1. 处理明文字典
	if len(plainFiles) > 0 {
		if err := appendToBuiltin(builtinPlain, plainFiles); err != nil {
			logging.Errorf("Failed to append plain dicts to %s: %v", builtinPlain, err)
			return err
		}
	}

	// 2. 处理 Salt 字典
	if len(secretFiles) > 0 {
		if err := appendToBuiltin(builtinSalt, secretFiles); err != nil {
			logging.Errorf("Failed to append secret dicts to %s: %v", builtinSalt, err)
			return err
		}
	}

	return nil
}

func dictInitAction(engine *cracker.Engine, opts *Options) (err error) {
	temps := tempFiles{remove: opts.RemoveTemp}
	defer temps.cleanup(&err)
	algorithms := algo.FilterNeedAddToPredbAlogs(algo.GetAlgorithmsByKeys(opts.AlgoKeys, opts.AlgosPrecise))
	if len(algorithms) == 0 {
		return fmt.Errorf("no algorithms selected for pre-computation")
	}
	plains, _, err := temps.resolve(opts.UsedPlains, engine.RunCacheDir, "init_plain")
	if err != nil {
		return err
	}
	salts, _, err := temps.resolve(opts.UsedSecrets, engine.RunCacheDir, "init_secret")
	if err != nil {
		return err
	}
	if len(plains) == 0 {
		plains = []string{engine.GetBuiltinPlainPath()}
	}
	if len(salts) == 0 {
		salts = []string{engine.GetBuiltinSaltPath()}
	}
	return engine.CreatePredb(plains, salts, algorithms)
}

func appendToBuiltin(targetPath string, sourceFiles []string) (err error) {
	f, err := os.OpenFile(targetPath, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	targetInfo, err := f.Stat()
	if err != nil {
		return err
	}

	for _, srcPath := range sourceFiles {
		// 避免自我追加
		if srcPath == targetPath {
			logging.Warnf("append to builtin ignore srcpath == targetpath: %s", srcPath)
			continue
		}

		src, err := os.Open(srcPath)
		if err != nil {
			return fmt.Errorf("open dictionary %s: %w", srcPath, err)
		}
		sourceInfo, err := src.Stat()
		if err != nil {
			return errors.Join(err, src.Close())
		}
		if os.SameFile(targetInfo, sourceInfo) {
			if err := src.Close(); err != nil {
				return err
			}
			continue
		}
		// Keep the existing final entry separate when the dictionary lacks a newline.
		info, err := f.Stat()
		if err != nil {
			return errors.Join(err, src.Close())
		}
		if info.Size() > 0 {
			var last [1]byte
			if _, err := f.ReadAt(last[:], info.Size()-1); err != nil {
				return errors.Join(err, src.Close())
			}
			if last[0] != '\n' {
				if _, err := f.WriteString("\n"); err != nil {
					return errors.Join(err, src.Close())
				}
			}
		}

		// 追加内容
		if _, err := io.Copy(f, src); err != nil {
			src.Close()
			return fmt.Errorf("failed copy from %s: %w", srcPath, err)
		}
		// 确保换行
		if err := src.Close(); err != nil {
			return err
		}
		if _, err := f.WriteString("\n"); err != nil {
			return err
		}
	}
	return nil
}
