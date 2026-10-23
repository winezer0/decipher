package cracker

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"time"

	"github.com/winezer0/xutils/progress"

	"github.com/winezer0/xutils/logging"

	"decipher/internal/algo"

	"github.com/schollz/progressbar/v3"
)

func (e *Engine) RunHashCrack(targets []HashSaltTarget, plainFiles []string, secretFiles []string, hashAlgos []algo.Algorithm) []CrackerResult {
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
	reuseStrategies := len(plainDictSources) > 1 && purePreparedAlgorithms(hashAlgos)
	var prepared *crackStrategies
	for _, source := range plainDictSources {
		logging.Infof("RunHashCrack processing dictionary: %s", source.Name)

		reader, err := source.Provider()
		if err != nil {
			logging.Errorf("Failed to open dictionary %s: %v", source.Name, err)
			continue
		}

		// Calculate total size for progress bar
		var bar *progressbar.ProgressBar
		var crackReader io.Reader = reader
		size, err := reader.Seek(0, io.SeekEnd)
		if err == nil {
			if _, seekErr := reader.Seek(0, io.SeekStart); seekErr == nil {
				crackReader = plaintextSizedReader{Reader: reader, size: size}
			}

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
		var crackerResults []CrackerResult
		if reuseStrategies {
			if prepared == nil {
				strategies := e.prepareCrackStrategies(targets, hashAlgos)
				prepared = &strategies
			}
			crackerResults = e.runPreparedHashCrack(*prepared, saltProviders, crackReader, startTime, bar, e.SaltPrefix != "" || e.SaltSuffix != "")
		} else {
			crackerResults = e.runHashCrackWithDictStream(targets, hashAlgos, saltProviders, crackReader, startTime, bar)
		}
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
	plainLine    string
	salts        []string // 同一盐批次可由多个任务共享，发布后禁止修改。
	affixedSalts *preparedSaltBatch
}

type preparedSaltBatch struct{ values []string }

type crackDispatchOptions struct{ shareSaltAffixes, skipFixed, skipDynamic bool }

func purePreparedAlgorithms(algos []algo.Algorithm) bool {
	if len(algos) == 0 {
		return false
	}
	for _, a := range algos {
		recover, _ := algo.PrepareRecover(a)
		if recover == nil {
			return false
		}
	}
	return true
}

// crackStrategy 保存原始目标和按用户顺序筛选的算法，发布后只读。
type crackStrategy struct {
	target     HashSaltTarget
	validAlgos []*crackAlgorithm
	secret     string // 固定轮中已附加前后缀的盐。
	prepared   *algo.PreparedDigest
}

type crackAlgorithm struct {
	algo.Algorithm
	recoverPrepared algo.PreparedRecover
	tokenLength     int
}

type crackStrategies struct {
	fixed            []crackStrategy
	dynamic          []crackStrategy
	fixedPlainDigest func(string) algo.PreparedDigest
}

func (e *Engine) prepareCrackStrategies(targets []HashSaltTarget, algos []algo.Algorithm) crackStrategies {
	var strategies crackStrategies
	bindings := make([]crackAlgorithm, len(algos))
	for i, alg := range algos {
		recover, tokenLength := algo.PrepareRecover(alg)
		bindings[i] = crackAlgorithm{Algorithm: alg, recoverPrepared: recover, tokenLength: tokenLength}
	}
	var preparedTargets []algo.PreparedDigest
	// Reuse temporary classification storage; published references live in
	// bounded blocks so growing an arena never retains abandoned copies.
	var scratch []*crackAlgorithm
	if len(targets) >= 16 {
		scratch = make([]*crackAlgorithm, 2*len(bindings))
	}
	var references []*crackAlgorithm
	for index, target := range targets {
		var fixed, dynamic []*crackAlgorithm
		if scratch != nil {
			fixed = scratch[:0:len(bindings)]
			dynamic = scratch[len(bindings) : len(bindings) : 2*len(bindings)]
		}
		needsPrepared := false
		var decoded algo.PreparedDigest
		decodedAttempted := false
		for i := range bindings {
			alg := &bindings[i]
			if alg.recoverPrepared != nil {
				if len(target.Hash) != alg.tokenLength {
					continue
				}
				if !decodedAttempted {
					decoded = algo.DecodeDigest(target.Hash)
					decodedAttempted = true
				}
				if !decoded.Valid() {
					continue
				}
			} else if !alg.Identify(target.Hash) {
				continue
			}
			needsPrepared = needsPrepared || alg.recoverPrepared != nil
			if target.Salt != "" || !alg.NeedSalt() {
				fixed = append(fixed, alg)
			} else {
				dynamic = append(dynamic, alg)
			}
		}
		if scratch != nil {
			required := len(fixed) + len(dynamic)
			if required > cap(references)-len(references) {
				capacity := 256
				if len(bindings) > 0 && len(targets)-index <= capacity/len(bindings) {
					capacity = (len(targets) - index) * len(bindings)
				}
				references = make([]*crackAlgorithm, 0, max(required, capacity))
			}
			start := len(references)
			references = append(references, fixed...)
			fixed = references[start:len(references):len(references)]
			start = len(references)
			references = append(references, dynamic...)
			dynamic = references[start:len(references):len(references)]
		}
		var prepared *algo.PreparedDigest
		if needsPrepared {
			if preparedTargets == nil {
				preparedTargets = make([]algo.PreparedDigest, len(targets))
			}
			preparedTargets[index] = decoded
			prepared = &preparedTargets[index]
		}
		if len(fixed) > 0 {
			if strategies.fixed == nil {
				strategies.fixed = make([]crackStrategy, 0, len(targets))
			}
			strategies.fixed = append(strategies.fixed, crackStrategy{target: target, validAlgos: fixed, secret: e.AffixSalt(target.Salt), prepared: prepared})
		}
		if len(dynamic) > 0 {
			if strategies.dynamic == nil {
				strategies.dynamic = make([]crackStrategy, 0, len(targets))
			}
			strategies.dynamic = append(strategies.dynamic, crackStrategy{target: target, validAlgos: dynamic, prepared: prepared})
		}
	}
	if len(strategies.fixed) >= 16 {
		first := strategies.fixed[0].validAlgos
		if len(first) == 1 {
			compute := algo.PreparePlainDigest(first[0].Algorithm)
			for _, strategy := range strategies.fixed {
				if len(strategy.validAlgos) != 1 || strategy.validAlgos[0] != first[0] {
					compute = nil
					break
				}
			}
			strategies.fixedPlainDigest = compute
		}
	}
	return strategies
}

func (e *Engine) runHashCrackWithDictStream(hashSaltTargets []HashSaltTarget, algos []algo.Algorithm, saltProviders []SaltProvider, reader io.Reader, startTime time.Time, bar *progressbar.ProgressBar) []CrackerResult {
	strategies := e.prepareCrackStrategies(hashSaltTargets, algos)
	shareAffixes := (e.SaltPrefix != "" || e.SaltSuffix != "") && purePreparedAlgorithms(algos)
	return e.runPreparedHashCrack(strategies, saltProviders, reader, startTime, bar, shareAffixes)
}

func (e *Engine) runPreparedHashCrack(strategies crackStrategies, saltProviders []SaltProvider, reader io.Reader, startTime time.Time, bar *progressbar.ProgressBar, shareAffixes bool) []CrackerResult {
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

	// 启动 Workers
	for i := 0; i < e.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.crackWorker(ctx, taskChan, resultChan, strategies)
		}()
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 生产者：读取明文 -> 读取 Salt 流 -> 生成任务
	options := crackDispatchOptions{shareSaltAffixes: shareAffixes, skipFixed: len(strategies.fixed) == 0, skipDynamic: len(strategies.dynamic) == 0}
	go e.crackProducer(ctx, taskChan, reader, saltProviders, bar, startTime, options)

	for res := range resultChan {
		mu.Lock()
		results = append(results, res)
		mu.Unlock()
	}

	return results
}
