package main

import (
	"decipher/internal/algo"
	"decipher/internal/cracker"
	"decipher/internal/export"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/winezer0/xutils/logging"
	"github.com/winezer0/xutils/utils"
)

func main() {
	opts, _ := InitOptionsArgs(1)
	useDicts := opts.DecDicts
	useSecrets := opts.DecSecrets

	// 初始化加解密引擎
	engine := cracker.NewEngine(opts.Workers, opts.DataDir)

	// 过滤用户想要使用的算法selectedAlgos，为空时使用所有，通过关键字匹配
	selectedAlgos := algo.GetAlgorithmsByKeys(opts.AlgoKeys)
	if len(selectedAlgos) == 0 {
		logging.Fatal("No algorithms be selected")
	}

	// 如果是加密模式 调用已选择算法进行加密输出
	if len(opts.EncryptText) > 0 {
		texts := cracker.ParseStringsToTargets(opts.EncryptText)
		salts := cracker.ParseStringsToTargets(opts.EncryptSalt)
		results := engine.RunEncrypt(texts, salts, selectedAlgos)
		for _, res := range results {
			fmt.Println(res)
		}
		os.Exit(0)
	}

	// 基于指定的算法更新预缓存字典
	if len(useDicts) > 0 || len(useSecrets) > 0 {
		engine.GenCacheDB(selectedAlgos, useDicts, useSecrets)
	}

	// 解析输入的目标信息为target格式
	basicTargets := cracker.ParseStringsToTargets(opts.Inputs)
	if len(basicTargets) == 0 {
		logging.Infof("No targets specified. Exiting.")
		os.Exit(0)
	}

	totalTargets := len(basicTargets)
	var allResults []cracker.CrackerResult

	// 1. 加载成功缓存（success.cache.csv）
	failureCacheFile := "decipher.failure.csv"
	successCacheFile := filepath.Join(engine.CacheDir, "success.cache.csv")
	crackedHashes := export.LoadSuccessCacheMap(successCacheFile)

	// 2. 过滤已破解的密文或者哈希
	var targets []cracker.Target
	if len(crackedHashes) > 0 {
		for _, t := range basicTargets {
			if cached, ok := crackedHashes[strings.ToLower(t.Hash)]; ok {
				logging.Infof("Found cached result for %s: %s", t.Hash, cached.Plaintext)
				allResults = append(allResults, cached)
				continue
			}
			targets = append(targets, t)
		}
	} else {
		targets = basicTargets
	}

	if len(targets) == 0 {
		logging.Infof("All targets found in cache.")
	}

	//　预先填充所有目标都是解密失败的情况，后续解密成功后删除
	finalFailedTargets := make(map[string]cracker.Target)
	for _, t := range targets {
		finalFailedTargets[t.Hash] = t
	}

	// 4. 算法分类：
	// 先过滤出使用预计算数据解密和非预计算数据解密的算法
	preDbAlgos := algo.FilterNeedsPrecomputAlgos(selectedAlgos)
	notPreDBAlgos := algo.FilterNotNeedsPrecomputAlgos(selectedAlgos)
	// 5. 执行预计算破解（RunLocalCrack）
	if len(targets) > 0 && len(preDbAlgos) > 0 {
		// 检查每个预计算数据算法的 pre-db 缓存是否存在，不存在时自动生成
		engine.InitCacheDB(preDbAlgos, useDicts, useSecrets)
		logging.Infof("Starting precomputed crack for %d targets using %d algorithm(s)...", len(targets), len(preDbAlgos))
		predbResults := engine.RunLocalCrack(targets, preDbAlgos)
		for _, res := range predbResults {
			delete(finalFailedTargets, res.Hash)
			allResults = append(allResults, res)
		}
		logging.Infof("Precomputed crack found: %d/%d\n\n", len(predbResults), len(targets))
	}

	// 6. 算法再次分类
	// 过滤 notPrecomputAlgos 算法中的 动态hash算法 dynamicAlgos和可逆加密算法encryptAlogs
	if len(finalFailedTargets) > 0 && len(notPreDBAlgos) > 0 {
		dynamicAlgos := algo.FilterDynamicAlgorithms(notPreDBAlgos)
		encryptAlgos := algo.FilterEncryptAlgorithms(notPreDBAlgos)

		// 获取未解密的密文列表
		var remainingTargets []cracker.Target
		for _, t := range finalFailedTargets {
			remainingTargets = append(remainingTargets, t)
		}

		// 先调用 dynamicAlgos 对未解密的密文进行解密 执行动态破解（RunDynamicCrack）
		// 避免部分情况下密文是hash也是可逆编码的情况
		if len(dynamicAlgos) > 0 && len(remainingTargets) > 0 {
			logging.Infof("Starting dynamic crack for %d targets using %d algorithm(s)...", len(remainingTargets), len(dynamicAlgos))
			dynaResults := engine.RunDynamicCrack(remainingTargets, useDicts, dynamicAlgos)
			for _, res := range dynaResults {
				delete(finalFailedTargets, res.Hash)
				allResults = append(allResults, res)
			}
			logging.Infof("Dynamic crack found: %d/%d\n\n", len(dynaResults), len(remainingTargets))

			// 更新 remainingTargets
			remainingTargets = nil
			for _, t := range finalFailedTargets {
				remainingTargets = append(remainingTargets, t)
			}
		}

		// 再调用 encryptAlogs 对未解密的密文进行解密 使用字典逐个验证
		if len(encryptAlgos) > 0 && len(remainingTargets) > 0 {
			logging.Infof("Starting decrypt crack for %d targets using %d algorithm(s)...", len(remainingTargets), len(encryptAlgos))
			decResults := engine.RunDecryptCrack(remainingTargets, useSecrets, encryptAlgos)
			for _, res := range decResults {
				delete(finalFailedTargets, res.Hash)
				allResults = append(allResults, res)
			}
			logging.Infof("decrypt crack found: %d/%d\n\n", len(decResults), len(remainingTargets))
		}
	}

	// 7. 导出结果并更新成功缓存
	logging.Infof("Total Found: %d/%d failure:%d details:\n %s", len(allResults), totalTargets, len(finalFailedTargets), utils.ToJSON(allResults))

	if len(allResults) > 0 {
		// Save to success cache
		if err := export.ExportCSV(successCacheFile, allResults); err != nil {
			logging.Infof("Success(%d) targets cached to %s", len(allResults), successCacheFile)
		}
		// Save to result file
		if err := export.ExportCSV(opts.Output, allResults); err != nil {
			logging.Infof("Results (%d) targets exported to %s", len(allResults), opts.Output)
		}
	}
	// Export failed targets to  CSV
	if len(finalFailedTargets) > 0 {
		if err := export.ExportFailureCSV(failureCacheFile, finalFailedTargets); err == nil {
			logging.Infof("Failed (%d) targets exported to %s", len(finalFailedTargets), failureCacheFile)
		}
	}
}
