package cracker

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/winezer0/xutils/progress"

	"github.com/winezer0/xutils/cacher"

	"github.com/winezer0/xutils/logging"

	"decipher/internal/algo"

	"github.com/schollz/progressbar/v3"
)

func (e *Engine) RunHashCrack(targets []HashSaltTarget, plainFiles []string, secretFiles []string, hashAlgos []algo.Algorithm, nohashCache bool) []CrackerResult {
	var allResults []CrackerResult
	if len(targets) == 0 {
		return allResults
	}

	if len(hashAlgos) == 0 {
		hashAlgos = algo.GetAllAlgorithms()
		logging.Warnf("algos is empty, will use all algos")
	}

	logging.Infof("Using %d hash algorithm(s):", len(hashAlgos))
	for _, a := range hashAlgos {
		logging.Infof("  - %s", a.Name())
	}
	// 加载明文字典文件
	plainDictSources := InitDictProvider(plainFiles)
	logging.Infof("Using %d dictionary source(s)", len(plainDictSources))

	// 加载盐提供者
	saltProviders := InitSaltProviders(secretFiles)
	logging.Infof("Using %d salt provider(s)", len(saltProviders))

	// 开始进行解密
	startTime := time.Now()
	for _, source := range plainDictSources {
		logging.Infof("Processing dictionary: %s", source.Name)

		reader, err := source.Provider()
		if err != nil {
			logging.Errorf("Failed to open dictionary %s: %v", source.Name, err)
			continue
		}

		// Calculate total size for progress bar
		var bar *progressbar.ProgressBar
		size, err := reader.Seek(0, io.SeekEnd)
		if err == nil {
			reader.Seek(0, io.SeekStart)

			// 计算总任务量 = 文件大小 * (Salt遍历次数 + 1)
			// +1 是因为我们增加了一个 "Fixed Pass" (处理自带Salt或无Salt算法)
			// 如果SaltProvider是Generator或File，Count()可能返回-1，此时无法预估总进度
			multiProvider := NewMultiSaltProvider(saltProviders)
			saltCount := multiProvider.Count()

			if saltCount >= 0 {
				totalSize := size * int64(saltCount+1)
				bar = progress.NewByteProgressBar(totalSize, fmt.Sprintf("Cracking %s", filepath.Base(source.Name)))
			} else {
				// 无法确定总大小时，使用Spinner
				bar = progress.NewSpinner(fmt.Sprintf("Cracking %s", filepath.Base(source.Name)))
			}
		} else {
			bar = progress.NewSpinner(fmt.Sprintf("Cracking %s", filepath.Base(source.Name)))
		}

		// 使用新的流式 Salt 处理方法
		crackerResults := e.runHashCrackWithDictStream(targets, hashAlgos, saltProviders, reader, startTime, nohashCache, bar)
		for _, res := range crackerResults {
			allResults = append(allResults, res)

			fmt.Printf("\n[+] Success! Hash Crack: %s\n", res.Hash)
			fmt.Printf("    Algorithm: %s\n", res.Algorithm)
			fmt.Printf("    Plain    : %s\n", res.Plaintext)
			fmt.Printf("    Salt     : %s\n", res.Salt)

		}

		if closer, ok := reader.(io.Closer); ok {
			closer.Close()
		}
	}

	logging.Infof("hash crack done in %v", time.Since(startTime))
	return allResults
}

// 任务单元：明文块 + Salt 块
type crackTask struct {
	plainLine string
	salts     []string
}

// crackStrategy defines the cracking strategy for a specific hash target
type crackStrategy struct {
	validAlgos   []algo.Algorithm
	anyNeedsSalt bool
}

func (e *Engine) runHashCrackWithDictStream(hashSaltTargets []HashSaltTarget, algos []algo.Algorithm, saltProviders []SaltProvider, reader io.Reader, startTime time.Time, nohashCache bool, bar *progressbar.ProgressBar) []CrackerResult {
	var results []CrackerResult
	var mu sync.Mutex

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 任务通道，传递 (plain, salts) 任务包
	// 减小缓冲区大小，强制生产者（读取文件）与消费者（Worker）同步
	// 这样进度条更新（由生产者触发）将更准确地反映实际处理进度
	taskChan := make(chan crackTask, e.workers)
	resultChan := make(chan CrackerResult, e.workers*10)

	var wg sync.WaitGroup

	targetStrategies := make(map[string]crackStrategy)
	// 将 hashSaltTargets 转换为更易查找的结构，如果有自带 salt 的话
	// 注意：这里 hashSaltTargets 中的 Salt 字段是目标自带的盐（如果有），而不是我们要枚举的盐
	// 如果目标自带盐，那么它应该只使用自带的盐，或者将自带盐作为枚举盐之一？
	// 这里的逻辑需要理清：
	// HashSaltTarget 中的 Salt 是指 format 为 hash:salt 时提取出的 salt。
	// 如果提供了这个 salt，通常意味着这个 hash 是用这个 salt 生成的。
	// 但如果用户还提供了 secretFiles (salt 字典)，是尝试字典中的 salt 还是只用自带 salt？
	// 原有逻辑是 ConvertToHashSaltsTarget 将目标自带 salt 和 字典 salt 组合。
	// 但现在 salt 是流式的，我们需要调整策略。

	// 策略调整：
	// 1. 对于自带 salt 的 target，它的 "枚举 salt 列表" 应该包含自带 salt。
	// 2. 对于不带 salt 的 target，完全依赖 saltProviders。
	// 为了统一，我们在 Worker 内部处理这两种情况。

	for _, t := range hashSaltTargets {
		var valid []algo.Algorithm
		anyNeedsSalt := false

		for _, a := range algos {
			if a.Identify(t.Hash) {
				valid = append(valid, a)
				if a.NeedSalt() {
					anyNeedsSalt = true
				}
			}
		}
		targetStrategies[t.Hash] = crackStrategy{
			validAlgos:   valid,
			anyNeedsSalt: anyNeedsSalt,
		}
	}

	// 初始化运行时缓存管理器 map
	cacheManagers := make(map[string]*cacher.CacheManager)
	for _, target := range hashSaltTargets {
		if _, exists := cacheManagers[target.Hash]; exists {
			continue
		}

		cachePath := ""
		if !nohashCache {
			cachePath = e.GetRuntimeCachePath(target.Hash, algos)
		}

		hashCM := cacher.NewCacheManager(cachePath)
		cacheManagers[target.Hash] = hashCM
		defer hashCM.Close()
	}

	// 启动 Workers
	for i := 0; i < e.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
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
								cacheAlgo, cachePlain, cacheSalt := RecoverKeywords(cachedValue)
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
							plain, err := alg.Recover(target.Hash, salt, plainLine)
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
		}()
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 生产者：读取明文 -> 读取 Salt 流 -> 生成任务
	go e.crackProducer(ctx, taskChan, reader, saltProviders, bar, startTime)

	for res := range resultChan {
		mu.Lock()
		results = append(results, res)
		mu.Unlock()
	}

	return results
}

func genCachedKey(plain string, salt string) string {
	element := []string{salt, plain}
	return strings.Join(element, ConcatSymbol)
}
