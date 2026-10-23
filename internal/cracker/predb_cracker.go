package cracker

import (
	"bufio"
	"context"
	"fmt"
	"github.com/winezer0/decipher/internal/algo/types"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	utils "github.com/winezer0/xutils/strutils"
	logging "github.com/winezer0/zaplogs"

	"github.com/winezer0/decipher/internal/algo"
)

func (e *Engine) RunPredbCrack(targets []HashSaltTarget, selectedAlgos []algo.Algorithm) []CrackerResult {
	if len(selectedAlgos) == 0 {
		logging.Warnf("specified local crack pre-compute algos is empty, use all")
		selectedAlgos = algo.FilterNeedAddToPredbAlogs(algo.GetAllAlgorithms())
	}

	selectedAlgoNames := algo.GetAlgorithmNames(selectedAlgos)

	var allResults []CrackerResult
	seen := make(map[string]struct{})

	if len(targets) == 0 {
		return allResults
	}

	// 1. 构建共享 TargetMap
	targetMap := BuildTargetMap(targets)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	crackerResults := make(chan CrackerResult)
	startTime := time.Now()
	var wg sync.WaitGroup

	// 3. 限制并发文件打开数
	// 使用 semaphore 限制并发数，防止 too many open files
	// 默认限制为 64，或者可以使用 e.workers 如果它被用于此目的
	concurrency := 64
	if e.workers > 0 {
		concurrency = e.workers
	}
	sem := make(chan struct{}, concurrency)

	dbDir := e.predbScopeDir()
	cacheFiles, err := os.ReadDir(dbDir)
	if err != nil {
		logging.Errorf("Failed to read cache directory: %v", err)
		return allResults
	}

	go func() {
		for _, cacheFile := range cacheFiles {
			if cacheFile.IsDir() || !strings.HasPrefix(cacheFile.Name(), PredbPrefix) || !strings.HasSuffix(cacheFile.Name(), PredbSuffix) {
				continue
			}

			algoName := getAlgoNameFromCacheFile(cacheFile)
			if !utils.StringHasOneKey(algoName, selectedAlgoNames, true) {
				continue
			}

			alg := algo.GetAlgorithmByName(algoName)
			if alg == nil {
				continue
			}

			// 获取算法类型
			algoType := alg.GetAlgoType()

			// 获取信号量，限制并发
			sem <- struct{}{}
			wg.Add(1)
			go func(cFile os.DirEntry, aName string, aType types.AlgoType) {
				defer wg.Done()
				defer func() { <-sem }() // 释放信号量

				cacheDbPath := filepath.Join(dbDir, cFile.Name())
				fobj, err := os.Open(cacheDbPath)
				if err != nil {
					logging.Errorf("Failed to open cache file %s: %v", cacheDbPath, err)
					return
				}
				defer fobj.Close()

				e.PredbCrack(ctx, targetMap, fobj, crackerResults, aName, aType)
			}(cacheFile, algoName, algoType)
		}

		wg.Wait()
		close(crackerResults)
	}()

	for res := range crackerResults {
		// 防止重复输出
		dedupeKey := res.CalcHash()
		if _, ok := seen[dedupeKey]; ok {
			continue
		} else {
			seen[dedupeKey] = struct{}{}
		}

		allResults = append(allResults, res)
		fmt.Printf("\n[+] Success! Predb Crack: %s\n", res.Hash)
		fmt.Printf("    Algorithm: %s\n", res.Algorithm)
		fmt.Printf("    Plain    : %s\n", res.Plaintext)
		fmt.Printf("    Salt     : %s\n", res.Salt)
	}

	logging.Infof("Local crack done in %v", time.Since(startTime))
	return allResults
}

func (e *Engine) PredbCrack(ctx context.Context, targetMap map[string][]HashSaltTarget, dict io.Reader, results chan<- CrackerResult, algoName string, algoType types.AlgoType) {
	scanner := bufio.NewScanner(dict)
	for scanner.Scan() {
		line := scanner.Text()

		// 快速检查：只解析 Hash 部分，避免全行解析的开销
		idx := strings.Index(line, ConcatSymbol)
		if idx == -1 {
			continue
		}
		hash := line[:idx]

		if matchedTargets, ok := targetMap[hash]; ok {
			// 只有命中目标时才进行完整解析
			_, salt, plain, err := ParseHashLine(line, ConcatSymbol)
			if err != nil {
				continue
			}

			for _, matchedTarget := range matchedTargets {
				result := CrackerResult{
					Hash:      matchedTarget.Hash,
					Algorithm: algoName,
					AlgoType:  string(algoType),
					Plaintext: plain,
					Salt:      salt,
				}
				select {
				case <-ctx.Done():
					return
				case results <- result:
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		logging.Errorf("Scanner error in PredbCrack: %v", err)
	}
}
