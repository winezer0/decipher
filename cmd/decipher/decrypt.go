package main

import (
	"decipher/internal/algo"
	"decipher/internal/cracker"
	"decipher/internal/export"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/winezer0/xutils/logging"
	"github.com/winezer0/xutils/utils"
)

// decryptAction
// 作用：按照预期流程执行解密：
// 1. 过滤已缓存成功的目标
// 2. 使用预计算缓存（predb）进行破解
// 3. 使用静态/动态哈希进行字典破解
// 4. 使用加密解密器进行密文解密
func decryptAction(engine *cracker.Engine, opts *Options) error {
	// 将用户输入的目标转为文件
	hashesFiles, hashesTemp := resolveDictsPrefix(opts.Hashes, engine.RunCacheDir, "dec_hashes")
	logging.Infof("choices hashes %s to files: %s, temp: %s", opts.Hashes, hashesFiles, hashesTemp)
	if len(hashesFiles) == 0 {
		return fmt.Errorf("not valid hashes target was parsed :%s", opts.Hashes)
	}
	// 解析输入的目标信息为target格式
	basicTargets := cracker.ParseFilesToTargets(hashesFiles)
	if len(basicTargets) == 0 {
		return fmt.Errorf("parse files to targets is empty: %v", hashesFiles)
	}

	// 将用户输入的明文字典文件格式进行转换 最终实现只输入文件格式
	plainFiles, plainTemp := resolveDictsPrefix(opts.UsedPlains, engine.RunCacheDir, "dec_plain")
	logging.Infof("choices plain files: %s, temp: %s", plainFiles, plainTemp)
	// 当用户没有指定任何有效明文字典时 使用默认字典
	if len(plainFiles) == 0 {
		plainFiles = []string{engine.GetBuiltinPlainPath()}
		logging.Infof("use builtin plain dicts: %v", plainFiles)
	}

	// 将用户输入的salt字典文件格式进行转换 最终实现只输入文件格式
	secretDicts, secretTemp := resolveDictsPrefix(opts.UsedSecrets, engine.RunCacheDir, "dec_secret")
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

	totalTargets := len(basicTargets)
	var allResults []cracker.CrackerResult

	// 1. 过滤已破解的密文或者哈希
	crackedHashes := export.LoadSuccessCacheMap(engine.GetSuccessCachePath())
	var targets []cracker.HashSaltTarget
	if len(crackedHashes) > 0 {
		for _, target := range basicTargets {
			if cached, ok := crackedHashes[strings.ToLower(target.Hash)]; ok {
				fmt.Printf("\n[+] Success! Result Cached: %s\n", target.Hash)
				fmt.Printf("    Plain    : %s\n\n", cached.Plaintext)

				allResults = append(allResults, cached)
				continue
			}
			targets = append(targets, target)
		}
	} else {
		targets = basicTargets
	}

	// 预先标记所有剩余目标为失败，后续逐步删除成功项
	failedTargetsMap := cracker.ConvertTargetsToMap(targets)

	// 2. 使用预计算缓存算法进行破解（predb）
	preDbAlgos := algo.FilterNeedAddToPredbAlogs(findAlgos)
	if len(failedTargetsMap) > 0 && len(preDbAlgos) > 0 {
		if !opts.NoPredbCrack {
			// 2. 使用预计算缓存进行破解（predb）
			// 自动检查或生成 predb 缓存
			if err := engine.CreatePredbWithCheck(plainFiles, secretDicts, preDbAlgos); err != nil {
				logging.Errorf("create predb with check error: %v", err)
				return err
			}

			logging.Infof("Starting predb crack for %d targets using %d algos...", len(failedTargetsMap), len(preDbAlgos))
			predbResults := engine.RunPredbCrack(cracker.LoadTargetsFromMap(failedTargetsMap), preDbAlgos)
			for _, res := range predbResults {
				delete(failedTargetsMap, res.Hash)
				allResults = append(allResults, res)
			}
			export.ExportCSV(engine.GetSuccessCachePath(), predbResults, false)
			logging.Infof("Predb crack found: %d/%d", len(predbResults), len(targets))
		} else {
			// 对支持缓存的静态hash算法也使用动态破解
			// 5. 使用predb算法进行hash计算，用于弥补部分情况下dict未进行预被字典生成的问题
			if len(failedTargetsMap) > 0 && len(preDbAlgos) > 0 {
				residue := cracker.LoadTargetsFromMap(failedTargetsMap)
				logging.Infof("Starting predb algos crack for %d targets using %d algos...", len(residue), len(preDbAlgos))
				results := engine.RunHashCrack(residue, plainFiles, secretDicts, preDbAlgos, opts.NohashCache)
				for _, res := range results {
					delete(failedTargetsMap, res.Hash)
					allResults = append(allResults, res)
				}
				export.ExportCSV(engine.GetSuccessCachePath(), results, false)
				logging.Infof("predb algos crack found: %d/%d", len(results), len(residue))
			}
		}
	}

	// 4. 使用静态/动态哈希进行字典破解
	notPredbAlgos := algo.FilterNotNeedAddToPredbAlogs(findAlgos)
	if len(failedTargetsMap) > 0 && len(notPredbAlgos) > 0 {
		// 4.1 静态哈希（计算速度快）
		staticAlgos := algo.FilterStaticAlgorithms(notPredbAlgos)
		if len(failedTargetsMap) > 0 && len(staticAlgos) > 0 {
			residue := cracker.LoadTargetsFromMap(failedTargetsMap)
			logging.Infof("Starting static crack for %d targets using %d algos...", len(residue), len(staticAlgos))
			results := engine.RunHashCrack(residue, plainFiles, secretDicts, staticAlgos, opts.NohashCache)
			for _, res := range results {
				delete(failedTargetsMap, res.Hash)
				allResults = append(allResults, res)
			}
			export.ExportCSV(engine.GetSuccessCachePath(), results, false)
			logging.Infof("Static crack found: %d/%d", len(results), len(residue))
		}

		// 4.2 动态哈希（需要运行时计算）
		dynamicAlgos := algo.FilterDynamicAlgorithms(notPredbAlgos)
		if len(failedTargetsMap) > 0 && len(dynamicAlgos) > 0 && !opts.NoDynaCrack {
			residue := cracker.LoadTargetsFromMap(failedTargetsMap)
			logging.Infof("Starting dynamic crack for %d targets using %d algos...", len(residue), len(dynamicAlgos))
			results := engine.RunHashCrack(residue, plainFiles, secretDicts, dynamicAlgos, opts.NohashCache)
			for _, res := range results {
				delete(failedTargetsMap, res.Hash)
				allResults = append(allResults, res)
			}
			export.ExportCSV(engine.GetSuccessCachePath(), results, false)
			logging.Infof("Dynamic crack found: %d/%d", len(results), len(residue))
		}
	}

	// 6. 使用加密解密器进行解密（可逆加密）
	decryptAlgos := algo.FilterEncryptAlgorithms(notPredbAlgos)
	if len(failedTargetsMap) > 0 && len(decryptAlgos) > 0 {
		residue := cracker.LoadTargetsFromMap(failedTargetsMap)
		logging.Infof("Starting decrypt crack for %d targets using %d algos...", len(residue), len(decryptAlgos))
		decResults := engine.RunDecrypt(residue, secretDicts, decryptAlgos)
		for _, res := range decResults {
			delete(failedTargetsMap, res.Hash)
			allResults = append(allResults, res)
		}
		export.ExportCSV(engine.GetSuccessCachePath(), decResults, false)
		logging.Infof("Decrypt crack found: %d/%d", len(decResults), len(residue))
	}

	outputFile := filepath.Join(opts.Output, fmt.Sprintf("%s.dec.%s", AppName, opts.OutputType))
	if strings.ToLower(opts.OutputType) == "json" {
		if err := export.ExportJSON(outputFile, allResults); err == nil {
			logging.Infof("Crack results exported to %s", outputFile)
		}
	} else {
		if err := export.ExportCSV(outputFile, allResults, true); err == nil {
			logging.Infof("Crack results exported to %s", outputFile)
		}
	}

	// 统计和记录失败的 Hash
	failedTargets := failedTargetsMap
	failedCount := len(failedTargets)
	logging.Infof("Decryption Summary: Total: %d, Success: %d, Failed: %d", totalTargets, len(allResults), failedCount)

	if len(failedTargets) > 0 {
		failureFile := filepath.Join(opts.Output, opts.FailureCache)
		if err := export.ExportFailureCSV(failureFile, failedTargets, true); err != nil {
			logging.Errorf("Failed to write failure cache: %v", err)
		} else {
			logging.Infof("Failure records written to %s", failureFile)
		}
	}

	// 清理缓存文件
	if opts.RemoveTemp {
		utils.ClearFiles(hashesTemp...)
		utils.ClearFiles(plainTemp...)
		utils.ClearFiles(secretTemp...)
	}
	return nil
}
