package main

import (
	"decipher/internal/algo"
	"decipher/internal/cracker"
	"fmt"
	"github.com/winezer0/xutils/logging"
	"github.com/winezer0/xutils/utils"
	"io"
	"os"
)

func addedAction(engine *cracker.Engine, opts *Options) error {
	// 将用户输入的字典文件格式进行转换 最终实现只输入文件格式
	plainFiles, plainTemp := resolveDictsPrefix(opts.UsedPlains, engine.RunCacheDir, "add_plain")
	logging.Infof("choices plain files: %s, temp: %s", plainFiles, plainTemp)
	// 当用户没有指定任何有效明文字典时 使用默认字典
	if len(plainFiles) == 0 {
		plainFiles = []string{engine.GetBuiltinPlainPath()}
		logging.Infof("use builtin plain dicts: %v", plainFiles)
	}

	// 当用户没有指定有效密钥字典时，将密钥字典设置设置为空
	secretFiles, secretTemp := resolveDictsPrefix(opts.UsedSecrets, engine.RunCacheDir, "add_secret")
	if len(secretFiles) == 0 {
		secretFiles = []string{}
		logging.Infof("use empty secret dicts: %v", secretFiles)
	}

	// 对于add模式 当用户没有添加字典时，使用内置字典和内置salt
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

	// 3. 基于用户输入的字典生成或更新 predb
	// 过滤静态算法和需要进行predb生成的算法
	predbAlogs := algo.FilterNeedAddToPredbAlogs(algo.GetAlgorithmsByKeys(opts.AlgoKeys))
	if err := engine.CreatePredb(plainFiles, secretFiles, predbAlogs); err != nil {
		logging.Errorf("Failed to create/update predb: %v", err)
		return err
	}

	// 清理临时文件
	if opts.RemoveTemp {
		utils.ClearFiles(plainTemp...)
		utils.ClearFiles(secretTemp...)
	}
	return nil
}

func appendToBuiltin(targetPath string, sourceFiles []string) error {
	f, err := os.OpenFile(targetPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, srcPath := range sourceFiles {
		// 避免自我追加
		if srcPath == targetPath {
			logging.Warnf("append to builtin ignore srcpath == targetpath: %s", srcPath)
			continue
		}

		src, err := os.Open(srcPath)
		if err != nil {
			logging.Warnf("Skipping %s: %v", srcPath, err)
			continue
		}

		// 追加内容
		if _, err := io.Copy(f, src); err != nil {
			src.Close()
			return fmt.Errorf("failed copy from %s: %w", srcPath, err)
		}
		// 确保换行
		f.WriteString("\n")
		src.Close()
	}
	return nil
}
