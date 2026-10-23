package cracker

import (
	"bufio"
	"decipher/internal/algo"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	utils "github.com/winezer0/xutils/pathutils"

	logging "github.com/winezer0/zaplogs"
)

type predbRes struct {
	algo  string
	plain string
	salt  string
	hash  string
}

// CreatePredb 基于 加密算法、明文字典列表、密钥字典列表 生成预计算hash 并自动添加到predb中
func (e *Engine) CreatePredb(plainDicts []string, secretDicts []string, selectAlgos []algo.Algorithm) error {
	logging.Info("CreatePredb Processing Cache Generation...")
	if len(selectAlgos) == 0 {
		selectAlgos = algo.GetAllAlgorithms()
	}

	// 过滤静态算法和需要进行predb生成的算法
	preDBAlgos := algo.FilterNeedAddToPredbAlogs(algo.FilterStaticAlgorithms(selectAlgos))
	if len(preDBAlgos) == 0 {
		return fmt.Errorf("no algos that need pre-computation to generate pre-db")
	}
	logging.Infof("current predb algos (%d) to be used", len(preDBAlgos))

	if err := utils.EnsureDir(e.PredbDir, false); err != nil {
		return fmt.Errorf("failed to create cache directory %s: %v", e.PredbDir, err)
	}

	// 初始化盐值提供者（支持文件、生成器等）
	var saltProvider SaltProvider
	providers := InitSaltProviders(secretDicts)
	saltProvider = NewMultiSaltProvider(providers)

	// 使用流式批处理进行并发预计算
	return e.genPredbConcurrency(preDBAlgos, plainDicts, saltProvider)
}

// genPredbConcurrency 并发生成缓存条目
func (e *Engine) genPredbConcurrency(algos []algo.Algorithm, plainFiles []string, saltProvider SaltProvider) error {
	// 分离算法
	var saltedAlgos []algo.Algorithm
	var unsaltedAlgos []algo.Algorithm
	for _, alg := range algos {
		if alg.NeedSalt() {
			saltedAlgos = append(saltedAlgos, alg)
		} else {
			unsaltedAlgos = append(unsaltedAlgos, alg)
		}
	}

	resultsChan := make(chan predbRes, e.workers*10)

	// 启动写入器
	writerDone := make(chan error, 1)
	go func() {
		var writeErr error
		files := make(map[string]*os.File)
		writers := make(map[string]*bufio.Writer)
		counts := make(map[string]int)
		defer func() {
			for name, w := range writers {
				if err := w.Flush(); err != nil {
					writeErr = errors.Join(writeErr, fmt.Errorf("flush pre-db %s: %w", name, err))
				}
			}
			for name, f := range files {
				if err := f.Close(); err != nil {
					writeErr = errors.Join(writeErr, fmt.Errorf("close pre-db %s: %w", name, err))
				}
			}
			writerDone <- writeErr
		}()

		// 预先打开文件
		for _, alg := range algos {
			algoName := alg.Name()
			if _, ok := writers[algoName]; ok {
				continue
			}
			dbPath := filepath.Join(e.PredbDir, fmt.Sprintf(PredbFileFormat, algoName))
			dbObj, err := os.OpenFile(dbPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				writeErr = errors.Join(writeErr, fmt.Errorf("open pre-db %s: %w", dbPath, err))
				continue
			}
			files[algoName] = dbObj
			writers[algoName] = bufio.NewWriterSize(dbObj, 256*1024)
			counts[algoName] = 0
		}

		for res := range resultsChan {
			if writeErr != nil {
				continue // 继续消费通道，避免生产者因写入失败而阻塞。
			}
			w, ok := writers[res.algo]
			if !ok {
				// 理论上不应该走到这里，因为前面已经预打开了
				fname := filepath.Join(e.PredbDir, fmt.Sprintf(PredbFileFormat, res.algo))
				f, err := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					writeErr = fmt.Errorf("open pre-db %s: %w", fname, err)
					continue
				}
				files[res.algo] = f
				w = bufio.NewWriterSize(f, 256*1024)
				writers[res.algo] = w
				counts[res.algo] = 0
			}

			element := []string{HashStringFormat(res.hash), res.salt, res.plain}
			entry := strings.Join(element, ConcatSymbol)
			if _, err := w.WriteString(entry + "\n"); err != nil {
				writeErr = fmt.Errorf("write pre-db %s: %w", res.algo, err)
				continue
			}
			counts[res.algo]++
			if counts[res.algo]%4096 == 0 {
				if err := w.Flush(); err != nil {
					writeErr = fmt.Errorf("flush pre-db %s: %w", res.algo, err)
				}
			}
		}
	}()

	startTime := time.Now()

	// 定义批处理函数
	processBatch := func(plains []string) {
		// 处理不需要盐的算法
		if len(unsaltedAlgos) > 0 {
			// logging.Infof("Processing batch unsalted algos with %d plains...", len(plains))
			plainsChan := make(chan string, e.workers*2)
			var uwg sync.WaitGroup

			for i := 0; i < e.workers; i++ {
				uwg.Add(1)
				go func() {
					defer uwg.Done()
					for line := range plainsChan {
						for _, alg := range unsaltedAlgos {
							hash, err := alg.Seal(e.AffixPasswd(line), "")
							if err == nil {
								resultsChan <- predbRes{
									algo:  alg.Name(),
									hash:  hash,
									salt:  "",
									plain: line,
								}
							}
						}
					}
				}()
			}

			// 发送明文
			for _, p := range plains {
				plainsChan <- p
			}
			close(plainsChan)
			uwg.Wait()
		}

		// 处理需要盐的算法
		if len(saltedAlgos) > 0 {
			// logging.Infof("Processing batch salted algos with salt provider...")
			saltsChan := saltProvider.GenerateStream(nil)
			var swg sync.WaitGroup

			for i := 0; i < e.workers; i++ {
				swg.Add(1)
				go func() {
					defer swg.Done()
					for salt := range saltsChan {
						for _, line := range plains {
							for _, alg := range saltedAlgos {
								hash, err := alg.Seal(e.AffixPasswd(line), e.AffixSalt(salt))
								if err == nil {
									resultsChan <- predbRes{
										algo:  alg.Name(),
										hash:  hash,
										salt:  salt,
										plain: line,
									}
								}
							}
						}
					}
				}()
			}
			swg.Wait()
		}
	}

	// 流式读取明文文件并分批处理
	batchSize := 10000
	var plainBatch []string
	var readErr error

	for _, path := range plainFiles {
		f, err := os.Open(path)
		if err != nil {
			readErr = fmt.Errorf("open plain file %s: %w", path, err)
			break
		}

		logging.Infof("GenPredb Processing plain file: %s", path)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				plainBatch = append(plainBatch, line)
				if len(plainBatch) >= batchSize {
					processBatch(plainBatch)
					plainBatch = plainBatch[:0]
				}
			}
		}
		if err := scanner.Err(); err != nil {
			readErr = fmt.Errorf("read plain file %s: %w", path, err)
		}
		if err := f.Close(); err != nil {
			readErr = errors.Join(readErr, err)
		}
		if readErr != nil {
			break
		}
	}

	// 处理剩余的批次
	if readErr == nil && len(plainBatch) > 0 {
		processBatch(plainBatch)
	}

	close(resultsChan)
	if err := errors.Join(readErr, <-writerDone); err != nil {
		return err
	}

	logging.Infof("Predb generation done in %v", time.Since(startTime))
	return nil
}

// CreatePredbWithCheck 检查并初始化预计算hash缓存
func (e *Engine) CreatePredbWithCheck(planDicts []string, secretDicts []string, preDbAlgos []algo.Algorithm) error {
	if e.IsEmptyPredbDir() {
		return e.CreatePredb(planDicts, secretDicts, preDbAlgos)
	}

	var errs []string
	for _, alg := range preDbAlgos {
		cacheFile := e.GetAlgoPredbPath(alg)
		if !utils.FileExists(cacheFile) {
			logging.Debugf("predb for %s not found, auto generating ...", alg.Name())
			if err := e.CreatePredb(planDicts, secretDicts, []algo.Algorithm{alg}); err != nil {
				logging.Errorf("create predb for %s error: %v", alg.Name(), err)
				errs = append(errs, fmt.Sprintf("algos:%s -> error:%s", alg.Name(), err.Error()))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, ";"))
	}
	return nil
}
