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
	cacheDir := opts.DataDir

	engine := cracker.NewEngine(opts.Workers, cacheDir)

	// 更新预缓存字典
	if len(opts.DecDicts) > 0 || len(opts.DecSecrets) > 0 {
		selectedAlgos := algo.GetAlgorithmsByNames(opts.AlgoKeys)
		engine.GenCacheDB(cacheDir, opts.DecDicts, opts.DecSecrets, opts.Workers, selectedAlgos)
	}

	// Handle Encryption Mode
	if len(opts.EncryptText) > 0 {
		texts := cracker.ParseStringsToTargets(opts.EncryptText)
		salts := cracker.ParseStringsToTargets(opts.EncryptSalt)
		algos := algo.GetAlgorithmsByNames(opts.AlgoKeys)

		if len(algos) == 0 {
			logging.Fatal("No algorithms selected for encryption")
		}

		results := cracker.RunEncryption(texts, salts, algos, opts.Workers)
		for _, res := range results {
			fmt.Println(res)
		}
		os.Exit(0)
	}

	targets := cracker.ParseStringsToTargets(opts.Inputs)
	totalTargets := len(targets)
	var allResults []cracker.CrackerResult

	// 1. 加载成功缓存（success.cache.csv）
	failureCache := "decipher.failure.csv"
	successCache := filepath.Join(cacheDir, "success.cache.csv")
	crackedHashes := export.LoadSuccessCacheMap(successCache)

	// 2. 过滤已破解的密文或者哈希
	if len(crackedHashes) > 0 {
		var pendingTargets []cracker.Target
		for _, t := range targets {
			if cached, ok := crackedHashes[strings.ToLower(t.Hash)]; ok {
				logging.Infof("Found cached result for %s: %s", t.Hash, cached.Plaintext)
				allResults = append(allResults, cached)
				continue
			}
			pendingTargets = append(pendingTargets, t)
		}
		targets = pendingTargets
	}

	if len(targets) == 0 && len(allResults) > 0 {
		logging.Infof("All targets found in cache.")
	} else if len(targets) == 0 {
		logging.Infof("No targets specified or all filtered. Exiting.")
		os.Exit(0)
	}

	// 3. 过滤用户想要使用的算法selectedAlgos，为空时使用所有，通过关键字匹配
	var selectedAlgos []algo.Algorithm
	if len(opts.AlgoKeys) > 0 {
		selectedAlgos = algo.GetAlgorithmsByNames(opts.AlgoKeys)
	} else {
		selectedAlgos = algo.GetAllAlgorithms()
	}

	if len(selectedAlgos) == 0 {
		logging.Fatal("No algorithms selected")
	}

	// 4. 算法分类：
	// 先过滤出使用预计算数据解密和非预计算数据解密的算法
	precomputAlgos := algo.FilterNeedsPrecomputAlgorithms(selectedAlgos)
	notPrecomputAlgos := algo.FilterNotNeedsPrecomputAlgorithms(selectedAlgos)

	failedTargets := make(map[string]cracker.Target)
	for _, t := range targets {
		failedTargets[t.Hash] = t
	}

	// 5. 执行预计算破解（RunLocalCrack）
	if len(targets) > 0 && len(precomputAlgos) > 0 {
		// 检查每个预计算数据算法的 pre-db 缓存是否存在，不存在时自动生成
		for _, alg := range precomputAlgos {
			cacheFile := filepath.Join(cacheDir, fmt.Sprintf("cache_%s.cache", alg.Name()))
			if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
				logging.Warnf("Cache for %s not found, generating...", alg.Name())
				engine.GenCacheDB(cacheDir, opts.DecDicts, opts.DecSecrets, opts.Workers, precomputAlgos)
				break // 生成一次即可包含所有算法
			}
		}

		precomputAlgoNames := algo.GetAlgorithmNames(precomputAlgos)
		logging.Infof("Starting precomputed crack for %d targets using %d algorithm(s)...", len(targets), len(precomputAlgos))
		results := engine.RunLocalCrack(targets, cacheDir, precomputAlgoNames)
		for _, res := range results {
			delete(failedTargets, res.Hash)
			allResults = append(allResults, res)
		}
		logging.Infof("Precomputed crack found: %d/%d\n\n", len(results), len(targets))
	}

	// 6. 算法再次分类
	// 过滤 notPrecomputAlgos 算法中的 动态hash算法 dynamicAlgos和可逆加密算法encryptAlogs
	if len(failedTargets) > 0 && len(notPrecomputAlgos) > 0 {
		dynamicAlgos := algo.FilterDynamicAlgorithms(notPrecomputAlgos)
		encryptAlgos := algo.FilterEncryptAlgorithms(notPrecomputAlgos)

		// 获取未解密的密文列表
		var remainingTargets []cracker.Target
		for _, t := range failedTargets {
			remainingTargets = append(remainingTargets, t)
		}

		// 先调用 dynamicAlgos 对未解密的密文进行解密 执行动态破解（RunDynamicCrack）
		// 避免部分情况下密文是hash也是可逆编码的情况
		if len(dynamicAlgos) > 0 && len(remainingTargets) > 0 {
			dynamicAlgoNames := algo.GetAlgorithmNames(dynamicAlgos)
			logging.Infof("Starting dynamic crack for %d targets using %d algorithm(s)...", len(remainingTargets), len(dynamicAlgos))
			results := engine.RunDynamicCrack(remainingTargets, opts.DecDicts, dynamicAlgoNames)
			for _, res := range results {
				delete(failedTargets, res.Hash)
				allResults = append(allResults, res)
			}
			logging.Infof("Dynamic crack found: %d/%d\n\n", len(results), len(remainingTargets))

			// 更新 remainingTargets
			remainingTargets = nil
			for _, t := range failedTargets {
				remainingTargets = append(remainingTargets, t)
			}
		}

		// 再调用 encryptAlogs 对未解密的密文进行解密 使用字典逐个验证
		if len(encryptAlgos) > 0 && len(remainingTargets) > 0 {
			encryptAlgoNames := algo.GetAlgorithmNames(encryptAlgos)
			logging.Infof("Starting encryption crack for %d targets using %d algorithm(s)...", len(remainingTargets), len(encryptAlgos))
			results := cracker.RunEncryptionCrack(remainingTargets, opts.DecSecrets, encryptAlgoNames, opts.Workers)
			for _, res := range results {
				delete(failedTargets, res.Hash)
				allResults = append(allResults, res)
			}
			logging.Infof("Encryption crack found: %d/%d\n\n", len(results), len(remainingTargets))
		}
	}

	// 7. 导出结果并更新成功缓存
	logging.Infof("Total Found: %d/%d failure:%d details:\n %s", len(allResults), totalTargets, len(failedTargets), utils.ToJSON(allResults))

	if len(allResults) > 0 {
		// Save to success cache
		if err := export.ExportCSV(successCache, allResults); err != nil {
			logging.Infof("Success(%d) targets cached to %s", len(allResults), successCache)
		}
		// Save to result file
		if err := export.ExportCSV(opts.Output, allResults); err != nil {
			logging.Infof("Results (%d) targets exported to %s", len(allResults), opts.Output)
		}
	}
	// Export failed targets to  CSV
	if len(failedTargets) > 0 {
		if err := export.ExportFailureCSV(failureCache, failedTargets); err == nil {
			logging.Infof("Failed (%d) targets exported to %s", len(failedTargets), failureCache)
		}
	}
}
