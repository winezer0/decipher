package main

import (
	"github.com/winezer0/decipher/internal/algo"
	"github.com/winezer0/decipher/internal/cracker"
	"github.com/winezer0/decipher/internal/export"
	"fmt"
	"os"
	"path/filepath"

	logging "github.com/winezer0/zaplogs"
)

func encryptAction(engine *cracker.Engine, opts *Options) (err error) {
	temps := tempFiles{remove: opts.RemoveTemp}
	defer temps.cleanup(&err)
	// 将用户输入的字典文件格式进行转换 最终实现只输入文件格式
	plainDicts, plainTemp, err := temps.resolve(opts.UsedPlains, engine.RunCacheDir, "enc_plain")
	if err != nil {
		return err
	}
	logging.Infof("choices plain files: %s, temp: %s", plainDicts, plainTemp)
	// 当用户没有指定任何有效明文字典时 直接退出
	if len(plainDicts) == 0 {
		return fmt.Errorf("no plain dicts be selected")
	}

	// 将用户输入的字典文件格式进行转换 最终实现只输入文件格式
	secretDicts, secretTemp, err := temps.resolve(opts.UsedSecrets, engine.RunCacheDir, "enc_secret")
	if err != nil {
		return err
	}
	logging.Infof("choices secret files: %s, temp: %s", secretDicts, secretTemp)
	// 当用户没有指定有效密钥字典时，将密钥字典设置设置为空
	if len(secretDicts) == 0 {
		logging.Infof("use empty secret dicts")
		secretDicts = []string{}
	}

	// 过滤用户想要使用的算法selectedAlgos，为空时使用所有，通过关键字匹配
	findAlgos := algo.GetAlgorithmsByKeys(opts.AlgoKeys, opts.AlgosPrecise)
	if len(findAlgos) == 0 {
		return fmt.Errorf("no algorithms be selected")
	}

	// 进行加密
	// 只保留可展示的小结果集，输出文件始终流式写入。
	previewLimit := len(algo.GetAllAlgorithms())
	preview := make([]cracker.EncryptResult, 0, previewLimit)
	showPreview := true
	outputFile := filepath.Join(opts.Output, fmt.Sprintf("%s.enc.%s", AppName, opts.OutputType))
	if err := checkEncryptOutputInputs(outputFile, plainDicts, secretDicts); err != nil {
		return err
	}
	err = export.ExportEncryptStream(outputFile, opts.OutputType, func(emit func(cracker.EncryptResult) error) error {
		return engine.RunEncryptStream(plainDicts, secretDicts, findAlgos, func(result cracker.EncryptResult) error {
			if showPreview {
				if len(preview) < previewLimit {
					preview = append(preview, result)
				} else {
					showPreview = false
					preview = nil
				}
			}
			return emit(result)
		})
	})
	if err != nil {
		return err
	}
	for _, result := range preview {
		fmt.Println(result)
	}
	return nil
}

// 流式写入前拒绝覆盖输入字典（包括硬链接和符号链接），避免读取过程中截断源文件。
func checkEncryptOutputInputs(output string, inputs ...[]string) error {
	info, err := os.Stat(output)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, paths := range inputs {
		for _, path := range paths {
			input, err := os.Stat(path)
			if err == nil && os.SameFile(info, input) {
				return fmt.Errorf("encryption output is also an input dictionary: %s", path)
			}
		}
	}
	return nil
}
