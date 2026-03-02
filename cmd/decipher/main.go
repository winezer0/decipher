package main

import (
	"decipher/internal/algo"
	"decipher/internal/cracker"
	"decipher/internal/export"
	"fmt"
	"os"
	"strings"

	"github.com/winezer0/xutils/cmdutils"

	"github.com/winezer0/xutils/logging"
	"github.com/winezer0/xutils/utils"
)

func main() {
	opts, _ := InitOptionsArgs(1)
	plainDicts, tempPlainDicts := cmdutils.ConvertStringsToFiles(opts.UsedDicts, true)
	secretDicts, tempSecretDicts := cmdutils.ConvertStringsToFiles(opts.UsedSecrets, true)
	logging.Infof("choices dict files: %s %s", plainDicts, secretDicts)
	logging.Infof("generate temp files: %s %s", tempPlainDicts, tempSecretDicts)

	// 解析操作类型
	modeType := cracker.ResolveMode(opts.Mode)
	logging.Infof("current mode type: %v", modeType)

	// 过滤用户想要使用的算法selectedAlgos，为空时使用所有，通过关键字匹配
	algos := algo.GetAlgorithmsByKeys(opts.AlgoKeys)
	if len(algos) == 0 {
		logging.Fatal("No algorithms be selected")
	}

	// 初始化加密引擎对象
	engine := cracker.NewEngine(opts.Workers, opts.PredbDir, opts.RunCacheDir)
	// 如果是初始化模式 调用已选择算法进行预计算hash生成
	if modeType == cracker.ModeAdded {
		// 初始化加解密引擎
		if err := engine.CreatePredb(plainDicts, secretDicts, algos); err == nil {
			logging.Infof("success create predb on %s", engine.PredbDir)
		}
	}

	// 如果是加密模式 调用已选择算法进行加密输出
	if modeType == cracker.ModeEncrypt {
		encrypt := engine.RunEncrypt(plainDicts, secretDicts, algos)
		// 少量结果直接输出到控制台中
		if len(encrypt) <= len(algo.GetAllAlgorithms()) {
			for _, res := range encrypt {
				fmt.Println(res)
			}
		}
		// 写入解密结果到文件中，方便用户进行预览
		utils.WriteLines(opts.Output, encrypt, true)
		logging.Infof("encrypt results written to file: %s", opts.Output)
	}

	// 如果是解密模式 调用已选择算法进行密文解密
	if modeType == cracker.ModeDecrypt {
		// 解析输入的目标信息为target格式
		basicTargets := cracker.ParseFilesToTargets(opts.Inputs)
		if len(basicTargets) == 0 {
			logging.Infof("No targets specified. Exiting.")
			os.Exit(0)
		}

		totalTargets := len(basicTargets)
		var allResults []cracker.CrackerResult

		// 1. 加载成功缓存（success.predb.csv）
		crackedHashes := export.LoadSuccessCacheMap(engine.GetSuccessCachePath())

		// 2. 过滤已破解的密文或者哈希
		var targets []cracker.HashSaltTarget
		if len(crackedHashes) > 0 {
			for _, target := range basicTargets {
				if cached, ok := crackedHashes[strings.ToLower(target.Hash)]; ok {
					logging.Infof("Found cached result for %s: %s", target.Hash, cached.Plaintext)
					allResults = append(allResults, cached)
					continue
				}
				targets = append(targets, target)
			}
		} else {
			targets = basicTargets
		}

		if len(targets) == 0 {
			logging.Infof("All targets found in cache.")
		}

		//　预先填充所有目标都是解密失败的情况，后续解密成功后删除
		failedTargetsMap := cracker.ConvertTargetsToMap(targets)

		// 4. 算法分类：
		// 先过滤出使用预计算数据解密和非预计算数据解密的算法
		preDbAlgos := algo.FilterNeedAddToPredbAlogs(algos)
		// 5. 执行预计算破解（RunPredbCrack）
		if len(preDbAlgos) > 0 {
			// 检查每个预计算数据算法的 pre-db 缓存是否存在，不存在时自动生成
			engine.CreatePredbWithCheck(preDbAlgos, plainDicts, secretDicts)
			logging.Infof("Starting predb crack for %d task using %d algos...", len(targets), len(preDbAlgos))
			predbResults := engine.RunPredbCrack(targets, preDbAlgos)
			for _, res := range predbResults {
				delete(failedTargetsMap, res.Hash)
				allResults = append(allResults, res)
			}
			logging.Infof("Predb crack found: %d/%d\n\n", len(predbResults), len(targets))
		}

		// 6. 算法再次分类
		// 过滤 notPrecomputAlgos 算法中的 动态hash算法 dynamicAlgos和可逆加密算法encryptAlogs
		notPredbAlgos := algo.FilterNotNeedAddToPredbAlogs(algos)
		if len(failedTargetsMap) > 0 && len(notPredbAlgos) > 0 {
			// 先调用 staticAlgos 对未解密的密文进行解密 执行动态破解
			staticAlgos := algo.FilterStaticAlgorithms(notPredbAlgos)
			if len(failedTargetsMap) > 0 && len(staticAlgos) > 0 {
				// 获取未解密的密文列表
				residue := cracker.CopyTargets(failedTargetsMap)
				logging.Infof("Starting static crack for %d targets using %d algorithm(s)...", len(residue), len(staticAlgos))
				results := engine.RunHashCrack(residue, plainDicts, secretDicts, staticAlgos, opts.NohashCache)
				for _, res := range results {
					delete(failedTargetsMap, res.Hash)
					allResults = append(allResults, res)
				}
				logging.Infof("static cracker found: %d/%d\n\n", len(results), len(residue))
			}

			// 再调用 dynamicAlgos 对未解密的密文进行解密 执行动态破解
			dynamicAlgos := algo.FilterDynamicAlgorithms(notPredbAlgos)
			if len(failedTargetsMap) > 0 && len(dynamicAlgos) > 0 {
				// 获取未解密的密文列表
				residue := cracker.CopyTargets(failedTargetsMap)
				logging.Infof("Starting dynamic crack for %d targets using %d algorithm(s)...", len(residue), len(dynamicAlgos))
				results := engine.RunHashCrack(residue, plainDicts, secretDicts, dynamicAlgos, opts.NohashCache)
				for _, res := range results {
					delete(failedTargetsMap, res.Hash)
					allResults = append(allResults, res)
				}
				logging.Infof("Dynamic cracker found: %d/%d\n\n", len(results), len(residue))
			}

			// 再调用 encryptAlogs 对未解密的密文进行解密 使用字典逐个验证
			decryptAlgos := algo.FilterEncryptAlgorithms(notPredbAlgos)
			if len(failedTargetsMap) > 0 && len(decryptAlgos) > 0 {
				// 获取未解密的密文列表
				residue := cracker.CopyTargets(failedTargetsMap)
				logging.Infof("Starting decrypt crack for %d targets using %d algorithm(s)...", len(residue), len(decryptAlgos))
				decResults := engine.RunDecrypt(residue, secretDicts, decryptAlgos)
				for _, res := range decResults {
					delete(failedTargetsMap, res.Hash)
					allResults = append(allResults, res)
				}
				logging.Infof("Decrypt cracker found: %d/%d\n\n", len(decResults), len(residue))
			}
		}

		// 7. 导出结果并更新成功缓存
		logging.Infof("Total Found: %d/%d failure:%d details:\n %s", len(allResults), totalTargets, len(failedTargetsMap), utils.ToJSON(allResults))
		if len(allResults) > 0 {
			// Save to success cache
			if err := export.ExportCSV(engine.GetSuccessCachePath(), allResults); err == nil {
				logging.Infof("Success(%d) targets cached to %s", len(allResults), engine.GetSuccessCachePath())
			}
			// Save to result file
			if strings.ToLower(opts.OutputType) == "json" {
				if err := export.ExportJSON(opts.Output, allResults); err == nil {
					logging.Infof("Results (%d) targets exported to %s", len(allResults), opts.Output)
				}
			} else {
				if err := export.ExportCSV(opts.Output, allResults); err == nil {
					logging.Infof("Results (%d) targets exported to %s", len(allResults), opts.Output)
				}
			}
		}

		// Export failed targets to  CSV
		if len(failedTargetsMap) > 0 && len(opts.FailureCache) > 0 {
			if err := export.ExportFailureCSV(opts.FailureCache, failedTargetsMap); err == nil {
				logging.Infof("Failed (%d) targets exported to %s", len(failedTargetsMap), opts.FailureCache)
			}
		}
	}

	//	清理临时文件
	if removed, errs := utils.ClearFiles(tempPlainDicts, tempSecretDicts); len(errs) > 0 {
		logging.Warnf("clean temp dicts or secret error: %v", errs)
	} else {
		logging.Debugf("clean temp dicts or secret success: %v", removed)
	}
}
