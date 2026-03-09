package cracker

import (
	"context"
	"decipher/internal/algo"

	"github.com/winezer0/xutils/cacher"
)

// crackWorker is the main function for worker goroutines
func (e *Engine) crackWorker(ctx context.Context, taskChan <-chan crackTask, resultChan chan<- CrackerResult,
	hashSaltTargets []HashSaltTarget, targetStrategies map[string]crackStrategy, cacheManagers map[string]*cacher.CacheManager) {

	for task := range taskChan {
		plainLine := task.plainLine
		currentSalts := task.salts

		if plainLine == "" {
			continue
		}

		// 区分 Fixed Pass (nil salts) 和 Dynamic Pass (non-nil salts)
		// Fixed Pass: 用于处理自带 Salt 的目标或不需要 Salt 的算法
		// Dynamic Pass: 用于处理需要从 SaltStream 获取 Salt 的目标
		isFixedPass := len(currentSalts) == 0

		for _, target := range hashSaltTargets {
			strategy, exists := targetStrategies[target.Hash]
			if !exists || len(strategy.validAlgos) == 0 {
				continue
			}

			var validAlgos []algo.Algorithm
			var finalSecrets []string

			if isFixedPass {
				// Fixed Pass 逻辑：
				// 1. 如果 Target 自带 Salt -> 使用自带 Salt 运行所有适用算法
				// 2. 如果 Target 无 Salt -> 运行不需要 Salt 的算法 (使用空 Salt)
				if target.Salt != "" {
					validAlgos = strategy.validAlgos
					finalSecrets = []string{target.Salt}
				} else {
					for _, alg := range strategy.validAlgos {
						if !alg.NeedSalt() {
							validAlgos = append(validAlgos, alg)
						}
					}
					if len(validAlgos) > 0 {
						finalSecrets = []string{""}
					}
				}
			} else {
				// Dynamic Pass 逻辑：
				// 1. 如果 Target 自带 Salt -> 跳过 (已在 Fixed Pass 处理)
				// 2. 如果 Target 无 Salt -> 运行需要 Salt 的算法 (使用 currentSalts)
				if target.Salt != "" {
					continue
				}
				for _, alg := range strategy.validAlgos {
					if alg.NeedSalt() {
						validAlgos = append(validAlgos, alg)
					}
				}
				if len(validAlgos) > 0 {
					finalSecrets = currentSalts
				}
			}

			if len(validAlgos) == 0 || len(finalSecrets) == 0 {
				continue
			}

			hashCM := cacheManagers[target.Hash]

			for _, salt := range finalSecrets {
				// 检查缓存: key = plaintext:salt
				cacheKey := genCachedKey(plainLine, salt)
				if cachedValue, exists := hashCM.GetString(cacheKey); exists {
					if len(cachedValue) > 0 {
						cacheAlgo, cachePlain, cacheSalt := ParseRecoverKey(cachedValue)
						result := CrackerResult{
							Hash:      target.Hash,
							AlgoType:  "cached",
							Algorithm: cacheAlgo,
							Plaintext: cachePlain,
							Salt:      cacheSalt,
						}
						resultChan <- result
						goto NextTarget // 找到结果，跳过后续 Salt
					}
					continue
				}

				cacheValue := ""
				found := false
				for _, alg := range validAlgos {
					// 这里的 validAlgos 已经在前面筛选过，无需再判断 NeedSalt
					plain, err := alg.Recover(target.Hash, e.AffixSalt(salt), e.AffixPasswd(plainLine))
					if err == nil {
						result := CrackerResult{
							Hash:      target.Hash,
							AlgoType:  string(alg.GetAlgoType()),
							Algorithm: alg.Name(),
							Plaintext: plain,
							Salt:      salt,
						}
						cacheValue = result.GetKeywords()
						select {
						case <-ctx.Done():
							return
						case resultChan <- result:
						}
						found = true
						break
					}
				}
				// 尝试完所有算法后， 记录缓存
				hashCM.Set(cacheKey, cacheValue)
				if found {
					goto NextTarget
				}
			}
		NextTarget:
		}
	}
}
