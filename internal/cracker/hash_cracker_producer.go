package cracker

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"strings"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/winezer0/xutils/logging"
)

// Size obtained by RunHashCrack's existing progress calculation; never read or
// seek a stream merely to choose its initial buffer.
type plaintextSizedReader struct {
	io.Reader
	size int64
}

// Only concrete readers with cheap, non-consuming size information get a smaller
// starting buffer. Unknown streams and larger inputs retain the existing size.
func plaintextScannerBufferSize(reader io.Reader) int {
	const smallBufferSize = 4096
	var size int64
	switch r := reader.(type) {
	case *strings.Reader:
		size = int64(r.Len())
	case *bytes.Reader:
		size = int64(r.Len())
	case *bytes.Buffer:
		size = int64(r.Len())
	case plaintextSizedReader:
		size = r.size
	default:
		return DefaultScannerBufferSize
	}
	if size >= 0 && size < smallBufferSize {
		return smallBufferSize
	}
	return DefaultScannerBufferSize
}

// crackProducer reads plaintexts from the reader and dispatches tasks to workers.
// It handles the combination of plaintexts and salts (Fixed Pass & Dynamic Pass).
func (e *Engine) crackProducer(ctx context.Context, taskChan chan<- crackTask, reader io.Reader, saltProviders []SaltProvider, bar *progressbar.ProgressBar, startTime time.Time, options ...crackDispatchOptions) {
	defer close(taskChan)
	if bar != nil {
		defer bar.Finish()
	}

	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 0, plaintextScannerBufferSize(reader))
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
			e.processBatch(ctx, taskChan, plainBatch, saltProviders, bar, options...)
			plainBatch = plainBatch[:0] // Clear slice, keep capacity
			logging.Infof("Processed %d lines... (%v)", count, time.Since(startTime))
		}
	}

	// Process remaining plaintexts
	if len(plainBatch) > 0 {
		e.processBatch(ctx, taskChan, plainBatch, saltProviders, bar, options...)
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
func (e *Engine) processBatch(ctx context.Context, taskChan chan<- crackTask, plains []string, saltProviders []SaltProvider, bar *progressbar.ProgressBar, options ...crackDispatchOptions) {
	if len(plains) == 0 {
		return
	}
	shareAffixes := len(options) > 0 && options[0].shareSaltAffixes

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

		saltBatchSize := saltBufferSize
		saltBatchCapacity := saltBufferCapacity(saltProviders)
		var saltBatch []string

		// 遍历 Salt 流
		for salt := range saltStream {
			if saltBatch == nil {
				saltBatch = make([]string, 0, saltBatchCapacity)
			}
			saltBatch = append(saltBatch, salt)

			// 当积攒了一批 Salt 后，与当前批次的明文进行组合
			if len(saltBatch) >= saltBatchSize {
				affixes := e.prepareSaltAffixes(saltBatch, len(plains), shareAffixes)
				for _, p := range plains {
					select {
					case <-ctx.Done():
						return
					case taskChan <- crackTask{plainLine: p, salts: saltBatch, affixedSalts: affixes}:
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
			affixes := e.prepareSaltAffixes(saltBatch, len(plains), shareAffixes)
			for _, p := range plains {
				select {
				case <-ctx.Done():
					return
				case taskChan <- crackTask{plainLine: p, salts: saltBatch[:len(saltBatch):len(saltBatch)], affixedSalts: affixes}:
					if bar != nil {
						bar.Add(len(p) + 1)
					}
				}
			}
		}
	}
}

func (e *Engine) prepareSaltAffixes(salts []string, plains int, enabled bool) *preparedSaltBatch {
	if !enabled || plains < 16 || (e.SaltPrefix == "" && e.SaltSuffix == "") {
		return nil
	}
	// Very sparse/empty salts may concatenate without allocating. Retain the
	// worker's reusable scratch path there instead of allocating a batch array.
	nonempty := 0
	for _, salt := range salts {
		if salt != "" {
			nonempty++
		}
	}
	if nonempty < (len(salts)+3)/4 {
		return nil
	}
	batch := &preparedSaltBatch{values: make([]string, len(salts))}
	for i, salt := range salts {
		batch.values[i] = e.AffixSalt(salt)
	}
	return batch
}
