package main

import (
	"decipher/internal/algo"
	"decipher/internal/cracker"
	"fmt"
	"path/filepath"

	"github.com/winezer0/xutils/logging"
	"github.com/winezer0/xutils/utils"
)

func encryptAction(engine *cracker.Engine, opts *Options) error {
	// 将用户输入的字典文件格式进行转换 最终实现只输入文件格式
	plainDicts, plainTemp := resolveDictsPrefix(opts.UsedPlains, engine.RunCacheDir, "enc_plain")
	logging.Infof("choices plain files: %s, temp: %s", plainDicts, plainTemp)
	// 当用户没有指定任何有效明文字典时 直接退出
	if len(plainDicts) == 0 {
		return fmt.Errorf("no plain dicts be selected")
	}

	// 将用户输入的字典文件格式进行转换 最终实现只输入文件格式
	secretDicts, secretTemp := resolveDictsPrefix(opts.UsedSecrets, engine.RunCacheDir, "enc_secret")
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
	encryptRes := engine.RunEncrypt(plainDicts, secretDicts, findAlgos)
	// 少量结果直接输出到控制台中
	if len(encryptRes) <= len(algo.GetAllAlgorithms()) {
		for _, res := range encryptRes {
			fmt.Println(res)
		}
	}

	// 清理临时文件
	if opts.RemoveTemp {
		utils.ClearFiles(plainTemp...)
		utils.ClearFiles(secretTemp...)
	}
	// 写入解密结果到文件中，方便用户进行预览
	outputFile := filepath.Join(opts.Output, fmt.Sprintf("%s.enc.%s", AppName, opts.OutputType))
	return utils.WriteLines(outputFile, encryptRes, true)
}
