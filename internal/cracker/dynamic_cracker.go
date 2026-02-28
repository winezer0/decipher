package cracker

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/winezer0/xutils/logging"

	"decipher/internal/algo"
	"decipher/internal/embeds"
)

func (e *Engine) RunDynamicCrack(targets []Target, dynamicDicts []string, algorithms []string) []CrackerResult {
	var allResults []CrackerResult

	if len(targets) == 0 {
		return allResults
	}

	dynamicAlgos := algo.GetDynamicAlgorithmsByNames(algorithms)
	if len(dynamicAlgos) == 0 {
		logging.Warn("No dynamic algorithms available for cracking.")
		return allResults
	}

	logging.Infof("Using %d dynamic algorithm(s):", len(dynamicAlgos))
	for _, a := range dynamicAlgos {
		logging.Infof("  - %s", a.Name())
	}

	logging.Infof("Using %d workers for dynamic hash cracking", e.workers)

	dictSources := e.getDynamicDictSources(dynamicDicts)
	logging.Infof("Using %d dictionary source(s)", len(dictSources))

	failedTargets := make(map[string]Target)
	hashCacheDir := ".hashcache"
	if err := os.MkdirAll(hashCacheDir, 0755); err != nil {
		logging.Errorf("Failed to create hashcache dir: %v", err)
	}

	for _, target := range targets {
		// Check existing cache
		hashSum := md5.Sum([]byte(target.Hash))
		hashHex := hex.EncodeToString(hashSum[:])
		cacheFileName := hashHex[:8] + ".dynamic.cache"
		cachePath := filepath.Join(hashCacheDir, cacheFileName)

		if content, err := os.ReadFile(cachePath); err == nil {
			plaintext := strings.TrimSpace(string(content))
			if plaintext != "" {
				logging.Infof("Found cached result for %s: %s", target.Hash, plaintext)
				allResults = append(allResults, CrackerResult{
					Hash:      target.Hash,
					Plaintext: plaintext,
					Salt:      target.Salt,
					Algorithm: "cached",
					AlgoType:  "cached",
				})
				continue
			}
		}
		failedTargets[target.Hash] = target
	}

	// Update targets to only those that failed (weren't cached)
	var pendingTargets []Target
	for _, t := range failedTargets {
		pendingTargets = append(pendingTargets, t)
	}
	targets = pendingTargets

	if len(targets) == 0 {
		return allResults
	}

	seenResults := make(map[string]bool)
	var mu sync.Mutex

	startTime := time.Now()

	for _, ds := range dictSources {
		logging.Infof("Processing dictionary: %s", ds.Name)

		reader, err := ds.Provider()
		if err != nil {
			logging.Errorf("Failed to open dictionary %s: %v", ds.Name, err)
			continue
		}

		results := e.runDynamicCrackWithDict(targets, dynamicAlgos, reader, startTime)

		for _, res := range results {
			resultKey := res.Hash + ":" + res.Plaintext
			mu.Lock()
			if seenResults[resultKey] {
				mu.Unlock()
				continue
			}
			seenResults[resultKey] = true
			mu.Unlock()

			if _, ok := failedTargets[res.Hash]; ok {
				delete(failedTargets, res.Hash)
				allResults = append(allResults, res)

				fmt.Printf("\n[+] Success! Hash: %s\n", res.Hash)
				fmt.Printf("    Algorithm: %s\n", res.Algorithm)
				fmt.Printf("    Plaintext: %s\n", res.Plaintext)

				// Write to cache
				hashSum := md5.Sum([]byte(res.Hash))
				hashHex := hex.EncodeToString(hashSum[:])
				cacheFileName := hashHex[:8] + ".dynamic.cache"
				cachePath := filepath.Join(hashCacheDir, cacheFileName)
				if err := os.WriteFile(cachePath, []byte(res.Plaintext), 0644); err != nil {
					logging.Errorf("Failed to write cache for %s: %v", res.Hash, err)
				}
			}
		}

		if closer, ok := reader.(io.Closer); ok {
			closer.Close()
		}
	}

	logging.Infof("Dynamic crack done in %v", time.Since(startTime))
	return allResults
}

func (e *Engine) runDynamicCrackWithDict(targets []Target, dynamicAlgos []algo.Algorithm, reader io.Reader, startTime time.Time) []CrackerResult {
	var results []CrackerResult
	var mu sync.Mutex

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	linesChan := make(chan string, e.workers*2)
	resultChan := make(chan CrackerResult, e.workers*10)

	var wg sync.WaitGroup

	for i := 0; i < e.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for line := range linesChan {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}

				for _, target := range targets {
					for _, alg := range dynamicAlgos {
						// 使用新的 Recover 方法验证哈希
						_, err := alg.Recover(target.Hash, target.Salt, line)
						if err == nil {
							select {
							case <-ctx.Done():
								return
							case resultChan <- CrackerResult{
								Hash:      target.Hash,
								Algorithm: alg.Name(),
								AlgoType:  string(alg.GetAlgoType()),
								Plaintext: line,
								Salt:      target.Salt,
							}:
							}
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
			case linesChan <- scanner.Text():
				count++
				if count%ProgressReportInterval == 0 {
					logging.Infof("Processed %d lines... (%v)", count, time.Since(startTime))
				}
			}
		}
		close(linesChan)

		if err := scanner.Err(); err != nil {
			logging.Errorf("Scanner error in runDynamicCrackWithDict: %v", err)
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

type dictReaderProvider func() (io.ReadSeeker, error)

type dictSource struct {
	Name     string
	Provider dictReaderProvider
}

func (e *Engine) getDynamicDictSources(dynamicDicts []string) []dictSource {
	var sources []dictSource

	if len(dynamicDicts) > 0 {
		for _, d := range dynamicDicts {
			dPath := d
			sources = append(sources, dictSource{
				Name: dPath,
				Provider: func() (io.ReadSeeker, error) {
					f, err := os.Open(dPath)
					if err != nil {
						return nil, err
					}
					return f, nil
				},
			})
		}
	} else {
		sources = append(sources, dictSource{
			Name: "Builtin Dict",
			Provider: func() (io.ReadSeeker, error) {
				return embeds.GetBuiltinDict(), nil
			},
		})
	}

	return sources
}
