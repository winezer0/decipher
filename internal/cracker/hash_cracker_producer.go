package cracker

import (
	"bufio"
	"context"
	"io"
	"strings"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/winezer0/xutils/logging"
)

// crackProducer reads plaintexts from the reader and dispatches tasks to workers.
// It handles the combination of plaintexts and salts (Fixed Pass & Dynamic Pass).
func (e *Engine) crackProducer(ctx context.Context, taskChan chan<- crackTask, reader io.Reader, saltProviders []SaltProvider, bar *progressbar.ProgressBar, startTime time.Time) {
	defer close(taskChan)
	if bar != nil {
		defer bar.Finish()
	}

	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 0, DefaultScannerBufferSize)
	scanner.Buffer(buf, MaxScannerTokenSize)

	// Batch processing strategy:
	// Read a batch of plaintexts, then iterate through all salts for this batch.
	// This reduces the overhead of re-generating salt streams for every single plaintext,
	// especially when salts are generated dynamically or read from a large file.
	plainBatchSize := 10000 // Process 10,000 plaintexts per batch
	var plainBatch []string

	count := 0
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		// Even empty lines contribute to reading progress (bytes read),
		// though we skip processing them.
		// Approximate line bytes (content + newline).
		lineBytes := int64(len(text) + 1)

		if text == "" {
			// Skip empty lines but update progress bar
			if bar != nil {
				// Note: If multiple salt passes exist, this only updates for the "read" pass.
				// But since empty lines are rare and fast, the impact on total progress accuracy is negligible.
				bar.Add64(lineBytes)
			}
			continue
		}

		plainBatch = append(plainBatch, text)
		count++

		if len(plainBatch) >= plainBatchSize {
			e.processBatch(ctx, taskChan, plainBatch, saltProviders, bar)
			plainBatch = plainBatch[:0] // Clear slice, keep capacity
			logging.Infof("Processed %d lines... (%v)", count, time.Since(startTime))
		}
	}

	// Process remaining plaintexts
	if len(plainBatch) > 0 {
		e.processBatch(ctx, taskChan, plainBatch, saltProviders, bar)
	}

	if err := scanner.Err(); err != nil {
		logging.Errorf("Scanner error in crackProducer: %v", err)
	}
}

// processBatch processes a batch of plaintexts.
// It generates tasks for both "Fixed Pass" (no salt/built-in salt) and "Dynamic Pass" (salt stream).
//
// 运行逻辑分析：
// 1. Fixed Pass (固定轮):
//   - 目的: 处理不需要 Salt 的算法 (如 MD5) 或 Target 自带 Salt 的情况。
//   - 操作: 为每个明文生成一个 salt 为 nil 的任务。
//   - 进度: 每次分发任务后，更新进度条 (Add(len(p) + 1))。
//
// 2. Dynamic Pass (动态轮):
//   - 目的: 处理需要额外 Salt 的算法 (如 Md5(pass+salt))。
//   - 操作: 如果存在 SaltProviders，则遍历生成的 Salt 流。
//   - 优化: 采用 SaltBatch (1000) 批量分发，即 "1个明文 + 1000个Salt" 打包成一个任务 (实际上是 Task{p, salts})。
//   - 进度: 同样在分发任务后更新进度条。
func (e *Engine) processBatch(ctx context.Context, taskChan chan<- crackTask, plains []string, saltProviders []SaltProvider, bar *progressbar.ProgressBar) {
	if len(plains) == 0 {
		return
	}

	// Phase 1: Fixed Pass
	// 处理无 Salt 需求或自带 Salt 的情况
	for _, p := range plains {
		select {
		case <-ctx.Done():
			return
		case taskChan <- crackTask{plainLine: p, salts: nil}:
			// 更新进度条
			if bar != nil {
				// +1 代表换行符或分隔符，保持字节计数一致性
				bar.Add(len(p) + 1)
			}
		}
	}

	// Phase 2: Dynamic Pass (Stream)
	// 如果配置了额外的 Salt 字典/生成器，则进行组合测试
	if len(saltProviders) > 0 {
		multiProvider := NewMultiSaltProvider(saltProviders)
		saltStream := multiProvider.GenerateStream(ctx.Done())

		saltBatchSize := 1000
		var saltBatch []string

		// 遍历 Salt 流
		for salt := range saltStream {
			if saltBatch == nil {
				saltBatch = make([]string, 0, saltBatchSize)
			}
			saltBatch = append(saltBatch, salt)

			// 当积攒了一批 Salt 后，与当前批次的明文进行组合
			if len(saltBatch) >= saltBatchSize {
				for _, p := range plains {
					select {
					case <-ctx.Done():
						return
					case taskChan <- crackTask{plainLine: p, salts: saltBatch}:
						if bar != nil {
							bar.Add(len(p) + 1)
						}
					}
				}
				// 已发布的批次由 Workers 共享只读；下一批使用新数组。
				saltBatch = nil
			}
		}

		// 处理剩余的 Salt
		if len(saltBatch) > 0 {
			for _, p := range plains {
				select {
				case <-ctx.Done():
					return
				case taskChan <- crackTask{plainLine: p, salts: saltBatch[:len(saltBatch):len(saltBatch)]}:
					if bar != nil {
						bar.Add(len(p) + 1)
					}
				}
			}
		}
	}
}
