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
	salts     []string
}

// crackStrategy defines the cracking strategy for a specific hash target
type crackStrategy struct {
	validAlgos   []algo.Algorithm
	anyNeedsSalt bool
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

	// 启动 Workers
	for i := 0; i < e.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.crackWorker(ctx, taskChan, resultChan, hashSaltTargets, targetStrategies)
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
