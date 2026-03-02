package cracker

import (
	"bufio"
	"context"
	"decipher/internal/algo/types"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/winezer0/xutils/logging"
	"github.com/winezer0/xutils/utils"

	"decipher/internal/algo"
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	crackerResults := make(chan CrackerResult)
	startTime := time.Now()
	var wg sync.WaitGroup

	cacheFiles, err := os.ReadDir(e.PredbDir)
	if err != nil {
		logging.Errorf("Failed to read cache directory: %v", err)
		return allResults
	}

	for _, cacheFile := range cacheFiles {
		if cacheFile.IsDir() || !strings.HasPrefix(cacheFile.Name(), PredbPrefix) || !strings.HasSuffix(cacheFile.Name(), PredbSuffix) {
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

		cacheDbPath := filepath.Join(e.PredbDir, cacheFile.Name())
		fobj, err := os.Open(cacheDbPath)
		if err != nil {
			logging.Errorf("Failed to open cache file %s: %v", cacheDbPath, err)
			continue
		}

		wg.Add(1)
		go func(f *os.File, aName string, aType types.AlgoType) {
			defer wg.Done()
			defer f.Close()
			e.PredbCrack(ctx, targets, f, crackerResults, aName, aType)
		}(fobj, algoName, algoType)
	}

	go func() {
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

func (e *Engine) PredbCrack(ctx context.Context, targets []HashSaltTarget, dict io.Reader, results chan<- CrackerResult, algoName string, algoType types.AlgoType) {
	targetMap := make(map[string][]HashSaltTarget)
	for _, t := range targets {
		hash := HashStringFormat(t.Hash)
		targetMap[hash] = append(targetMap[hash], t)
	}

	scanner := bufio.NewScanner(dict)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ConcatSymbol, 3)
		var hash, salt, plain string
		if len(parts) == 0 {
			continue
		}
		if len(parts) > 0 {
			hash = parts[0]
		}
		if len(parts) > 1 {
			salt = parts[1]
		}
		if len(parts) > 2 {
			plain = parts[2]
		}

		if matchedTargets, ok := targetMap[hash]; ok {
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
