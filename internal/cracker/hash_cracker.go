package cracker

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/winezer0/xutils/cacher"

	"github.com/winezer0/xutils/utils"

	"github.com/winezer0/xutils/logging"

	"decipher/internal/algo"
)

func (e *Engine) RunHashCrack(targets []HashSaltTarget, plainFiles []string, secretFiles []string, hashAlgos []algo.Algorithm, nohashCache bool) []CrackerResult {
	var allResults []CrackerResult
	if len(targets) == 0 {
		return allResults
	}

	if len(hashAlgos) == 0 {
		logging.Warn("No hash algorithms available for cracking.")
		return allResults
	}

	logging.Infof("Using %d hash algorithm(s):", len(hashAlgos))
	for _, a := range hashAlgos {
		logging.Infof("  - %s", a.Name())
	}
	// 加载明文字典文件
	dictSources := InitDictSources(plainFiles)
	logging.Infof("Using %d dictionary source(s)", len(dictSources))
	// 加载盐文件
	secrets := ParseFilesToStrings(secretFiles, true)
	secrets = utils.UniqueSlice(secrets, false, false)
	// 开始进行解密
	var mu sync.Mutex
	startTime := time.Now()
	for _, source := range dictSources {
		logging.Infof("Processing dictionary: %s", source.Name)

		reader, err := source.Provider()
		if err != nil {
			logging.Errorf("Failed to open dictionary %s: %v", source.Name, err)
			continue
		}

		crackerResults := e.runHashCrackWithDict(targets, hashAlgos, secrets, reader, startTime, nohashCache)
		for _, res := range crackerResults {
			mu.Lock()
			allResults = append(allResults, res)
			mu.Unlock()

			fmt.Printf("\n[+] Success! Hash Crack: %s\n", res.Hash)
			fmt.Printf("    Algorithm: %s\n", res.Algorithm)
			fmt.Printf("    Plain    : %s\n", res.Plaintext)
			fmt.Printf("    Salt     : %s\n", res.Salt)

		}

		if closer, ok := reader.(io.Closer); ok {
			closer.Close()
		}
	}

	logging.Infof("Dynamic crack done in %v", time.Since(startTime))
	return allResults
}

func (e *Engine) runHashCrackWithDict(hashSaltTargets []HashSaltTarget, algos []algo.Algorithm, salts []string, reader io.Reader, startTime time.Time, nohashCache bool) []CrackerResult {
	var results []CrackerResult
	var mu sync.Mutex

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	plainsChan := make(chan string, e.workers*2)
	resultChan := make(chan CrackerResult, e.workers*10)

	var wg sync.WaitGroup
	targetsWithSalts := ConvertToHashSaltsTarget(hashSaltTargets, salts)

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

	for i := 0; i < e.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for plainLine := range plainsChan {
				plainLine = strings.TrimSpace(plainLine)
				if plainLine == "" {
					continue
				}

				for _, newTarget := range targetsWithSalts {
					hashCM := cacheManagers[newTarget.hash]
					for _, salt := range newTarget.salts {
						// 检查缓存: key = plaintext:salt
						cacheKey := genCachedKey(salt, plainLine)
						if cachedValue, exists := hashCM.GetString(cacheKey); exists {
							if len(cachedValue) > 0 {
								cacheAlgo, cachePlain, cacheSalt := RecoverKeywords(cachedValue)
								result := CrackerResult{
									Hash:      newTarget.hash,
									AlgoType:  "cached",
									Algorithm: cacheAlgo,
									Plaintext: cachePlain,
									Salt:      cacheSalt,
								}
								resultChan <- result
								break
							}
							continue
						}

						cacheValue := ""
						found := false
						for _, alg := range algos {
							plain, err := alg.Recover(newTarget.hash, salt, plainLine)
							if err == nil {
								result := CrackerResult{
									Hash:      newTarget.hash,
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
							break
						}
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var readWg sync.WaitGroup
	readWg.Add(1)
	go func() {
		defer readWg.Done()
		scanner := bufio.NewScanner(reader)
		buf := make([]byte, 0, DefaultScannerBufferSize)
		scanner.Buffer(buf, MaxScannerTokenSize)

		count := 0
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			case plainsChan <- scanner.Text():
				count++
				if count%ProgressReportInterval == 0 {
					logging.Infof("Processed %d lines... (%v)", count, time.Since(startTime))
				}
			}
		}
		close(plainsChan)

		if err := scanner.Err(); err != nil {
			logging.Errorf("Scanner error in runHashCrackWithDict: %v", err)
		}
	}()

	for res := range resultChan {
		mu.Lock()
		results = append(results, res)
		mu.Unlock()
	}

	readWg.Wait()
	return results
}

func genCachedKey(salt string, plain string) string {
	element := []string{salt, plain}
	return strings.Join(element, ConcatSymbol)
}
