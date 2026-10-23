package cracker

import (
	"sync"
	"time"

	"github.com/winezer0/decipher/internal/algo"
	logging "github.com/winezer0/zaplogs"
)

// RunDecrypt 使用加密/编码算法对密文进行解密
// targets: 待解密的目标列表
// secrets: 密钥列表（可以是字典文件或直接密钥）
// algorithms: 加密算法名称列表
// workers: 并发工作数
func (e *Engine) RunDecrypt(targets []HashSaltTarget, secretDicts []string, decryptAlogs []algo.Algorithm) []CrackerResult {
	return e.runDecryptWithProviders(targets, InitSaltProviders(secretDicts), decryptAlogs)
}

// RunDecryptValues decrypts targets using literal in-memory secret values.
func (e *Engine) RunDecryptValues(targets []HashSaltTarget, secrets []string, decryptAlgos []algo.Algorithm) []CrackerResult {
	return e.runDecryptWithProviders(targets, InitValueSaltProviders(secrets), decryptAlgos)
}

// runDecryptWithProviders runs reversible algorithms with the provided secret sources.
func (e *Engine) runDecryptWithProviders(targets []HashSaltTarget, saltProviders []SaltProvider, decryptAlogs []algo.Algorithm) []CrackerResult {
	workers := e.workers
	var allResults []CrackerResult
	if len(targets) == 0 {
		return allResults
	}

	if len(decryptAlogs) == 0 {
		logging.Warn("No encryption algorithms available for cracking.")
		return allResults
	}

	logging.Infof("Using %d encryption algorithm(s):", len(decryptAlogs))
	for _, a := range decryptAlogs {
		logging.Infof("  - %s", a.Name())
	}

	// Calculate total count if possible (optional)

	startTime := time.Now()
	var wg sync.WaitGroup

	type job struct {
		target        HashSaltTarget
		secret        string
		affixedSecret string
		algorithm     algo.Algorithm
	}
	type targetAlgorithm struct {
		target    HashSaltTarget
		algorithm algo.Algorithm
	}

	jobs := make(chan job, workers*2)
	resultsChan := make(chan CrackerResult, workers*10)

	// 启动工作协程
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				plaintext, err := j.algorithm.Recover(j.target.Hash, j.affixedSecret, "")
				if err == nil && plaintext != "" {
					result := CrackerResult{
						Hash:      j.target.Hash,
						Algorithm: j.algorithm.Name(),
						AlgoType:  string(j.algorithm.GetAlgoType()),
						Plaintext: plaintext,
						Salt:      j.secret,
					}
					resultsChan <- result
				}
			}
		}()
	}

	// 关闭结果通道的协程
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	go func() {
		defer close(jobs)
		var saltedTargets []targetAlgorithm
		for _, target := range targets {
			for _, alg := range decryptAlogs {
				if matcher, ok := alg.(algo.DecryptFormatMatcher); ok && !matcher.CanDecryptFormat(target.Hash) {
					continue
				}
				if alg.NeedSalt() {
					saltedTargets = append(saltedTargets, targetAlgorithm{target: target, algorithm: alg})
					continue
				}
				jobs <- job{target: target, algorithm: alg}
			}
		}
		for _, provider := range saltProviders {
			stop := make(chan struct{})
			stream := provider.GenerateStream(stop)
			for secret := range stream {
				affixedSecret := e.AffixSalt(secret)
				for _, candidate := range saltedTargets {
					jobs <- job{
						target:        candidate.target,
						secret:        secret,
						affixedSecret: affixedSecret,
						algorithm:     candidate.algorithm,
					}
				}
			}
			close(stop)
		}
	}()

	for res := range resultsChan {
		allResults = append(allResults, res)
		logging.Infof("[+] Decrypt crack success! Hash: %s", res.Hash)
		logging.Infof("    Algorithm: %s", res.Algorithm)
		logging.Infof("    Plaintext: %s", res.Plaintext)
		logging.Infof("    Secret   : %s", res.Salt)
	}

	logging.Infof("Decrypt crack done in %v", time.Since(startTime))
	return allResults
}
