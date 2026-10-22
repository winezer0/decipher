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
	for _, source := range plainDictSources {
		logging.Infof("RunHashCrack processing dictionary: %s", source.Name)

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
		crackerResults := e.runHashCrackWithDictStream(targets, hashAlgos, saltProviders, reader, startTime, bar)
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
	salts     []string // 同一盐批次可由多个任务共享，发布后禁止修改。
}

// crackStrategy 保存原始目标和按用户顺序筛选的算法，发布后只读。
type crackStrategy struct {
	target     HashSaltTarget
	validAlgos []algo.Algorithm
	secret     string // 固定轮中已附加前后缀的盐。
}

type crackStrategies struct {
	fixed   []crackStrategy
	dynamic []crackStrategy
}

func (e *Engine) prepareCrackStrategies(targets []HashSaltTarget, algos []algo.Algorithm) crackStrategies {
	var strategies crackStrategies
	for _, target := range targets {
		var fixed, dynamic []algo.Algorithm
		for _, alg := range algos {
			if !alg.Identify(target.Hash) {
				continue
			}
			if target.Salt != "" || !alg.NeedSalt() {
				fixed = append(fixed, alg)
			} else {
				dynamic = append(dynamic, alg)
			}
		}
		if len(fixed) > 0 {
			if strategies.fixed == nil {
				strategies.fixed = make([]crackStrategy, 0, len(targets))
			}
			strategies.fixed = append(strategies.fixed, crackStrategy{target: target, validAlgos: fixed, secret: e.AffixSalt(target.Salt)})
		}
		if len(dynamic) > 0 {
			if strategies.dynamic == nil {
				strategies.dynamic = make([]crackStrategy, 0, len(targets))
			}
			strategies.dynamic = append(strategies.dynamic, crackStrategy{target: target, validAlgos: dynamic})
		}
	}
	return strategies
}

func (e *Engine) runHashCrackWithDictStream(hashSaltTargets []HashSaltTarget, algos []algo.Algorithm, saltProviders []SaltProvider, reader io.Reader, startTime time.Time, bar *progressbar.ProgressBar) []CrackerResult {
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

	strategies := e.prepareCrackStrategies(hashSaltTargets, algos)

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
	go e.crackProducer(ctx, taskChan, reader, saltProviders, bar, startTime)

	for res := range resultChan {
		mu.Lock()
		results = append(results, res)
		mu.Unlock()
	}

	return results
}
