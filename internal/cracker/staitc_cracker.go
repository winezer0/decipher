package cracker

import (
	"context"
	"decipher/internal/algo/types"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/winezer0/xutils/logging"
	"github.com/winezer0/xutils/utils"

	"decipher/internal/algo"
)

func (e *Engine) RunLocalCrack(targets []Target, selectedAlgos []algo.Algorithm) []CrackerResult {
	if len(selectedAlgos) == 0 {
		logging.Warnf("specified local crack pre-compute algos is empty, use all")
		selectedAlgos = algo.FilterNeedsPrecomputAlgos(algo.GetAllAlgorithms())
	}

	selectedAlgoNames := algo.GetAlgorithmNames(selectedAlgos)

	var allResults []CrackerResult

	if len(targets) == 0 {
		return allResults
	}

	failedTargets := make(map[string]Target)
	for _, target := range targets {
		failedTargets[target.Hash] = target
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	crackerResults := make(chan CrackerResult)
	startTime := time.Now()
	var wg sync.WaitGroup

	cacheFiles, err := os.ReadDir(e.CacheDir)
	if err != nil {
		logging.Errorf("Failed to read cache directory: %v", err)
		return allResults
	}

	for _, cacheFile := range cacheFiles {
		if cacheFile.IsDir() || !strings.HasSuffix(cacheFile.Name(), ".cache") {
			continue
		}

		algoName := getAlgoNameFromCacheFile(cacheFile)
		if !utils.StringHasOneKey(algoName, selectedAlgoNames, true) {
			continue
		}

		// 获取算法类型
		algoType := types.AlgoIsStatic
		if alg := algo.GetAlgorithmByName(algoName); alg != nil {
			algoType = alg.GetAlgoType()
		}

		cacheDbPath := filepath.Join(e.CacheDir, cacheFile.Name())
		fobj, err := os.Open(cacheDbPath)
		if err != nil {
			logging.Errorf("Failed to open cache file %s: %v", cacheDbPath, err)
			continue
		}

		wg.Add(1)
		go func(f *os.File, aName string, aType types.AlgoType) {
			defer wg.Done()
			defer f.Close()
			e.loacalPreDBCrack(ctx, targets, f, crackerResults, aName, aType)
		}(fobj, algoName, algoType)
	}

	go func() {
		wg.Wait()
		close(crackerResults)
	}()

	seenResults := make(map[string]bool)
	for res := range crackerResults {
		resultKey := res.Hash + ":" + res.Plaintext
		if seenResults[resultKey] {
			continue
		}
		seenResults[resultKey] = true

		e.mu.Lock()
		if _, ok := failedTargets[res.Hash]; ok {
			delete(failedTargets, res.Hash)
			allResults = append(allResults, res)
		}
		e.mu.Unlock()

		logging.Infof("\n[+] Success! Hash: %s", res.Hash)
		logging.Infof("    Algorithm: %s", res.Algorithm)
		logging.Infof("    Plaintext: %s", res.Plaintext)
		if res.Salt != "" {
			logging.Infof("    Salt     : %s", res.Salt)
		}
	}

	logging.Infof("Local crack done in %v", time.Since(startTime))
	return allResults
}

// 从缓存文件名中获取对应的算法
func getAlgoNameFromCacheFile(cacheFile os.DirEntry) string {
	cacheFileName := cacheFile.Name()
	algoName := strings.TrimPrefix(cacheFileName, "cache_")
	algoName = strings.TrimSuffix(algoName, ".cache")
	return algoName
}
