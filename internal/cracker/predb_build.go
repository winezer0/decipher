package cracker

import (
	"bufio"
	"decipher/internal/algo"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/winezer0/xutils/utils"

	"github.com/winezer0/xutils/logging"
)

type predbRes struct {
	algo  string
	plain string
	salt  string
	hash  string
}

// CreatePredb 基于 加密算法、明文字典列表、密钥字典列表 生成预计算hash 并自动添加到predb中
func (e *Engine) CreatePredb(plainDicts []string, secretDicts []string, selectAlgos []algo.Algorithm) error {
	logging.Info("Processing Cache Generation...")
	if len(selectAlgos) == 0 {
		selectAlgos = algo.GetAllAlgorithms()
	}

	preDBAlgos := algo.FilterNeedAddToPredbAlogs(selectAlgos)
	if len(preDBAlgos) == 0 {
		return fmt.Errorf("No algos that need pre-computation to generate pre-db")
	}
	logging.Infof("current predb algos (%d) to be used: %v", len(preDBAlgos), algo.GetAlgorithmNames(preDBAlgos))

	if err := utils.EnsureDir(e.PredbDir, false); err != nil {
		return fmt.Errorf("Failed to create cache directory %s: %v", e.PredbDir, err)
	}

	// 读取盐值列表（支持文件或字符串），如果为空则使用空盐兜底
	salts := ParseFilesToStrings(secretDicts, true)
	if len(salts) == 0 {
		logging.Warnf("no valid data was obtained, used empty salt: %v", secretDicts)
		salts = []string{""}
	}

	// 读取明文字典（支持文件或字符串），为空则使用内置字典
	plains := ParseFilesToStrings(plainDicts, true)
	if len(plains) == 0 {
		logging.Warnf("no valid data was obtained, used builtin plain: %v", secretDicts)
		plains = loadBuiltinPlainsEntries()
	}

	// 使用内存中的明文切片进行并发预计算
	e.genPredbConcurrency(preDBAlgos, plains, salts)

	return nil
}

// genPredbConcurrency 并发生成缓存条目
//
// 参数:
// - algos: 需要处理的算法列表
// - plains: 明文条目切片，已清理空白
// - salts: 盐值列表（可能为空串作为兜底）
func (e *Engine) genPredbConcurrency(algos []algo.Algorithm, plains []string, salts []string) {
	plainsChan := make(chan string, e.workers*2)
	resultsChan := make(chan predbRes, e.workers*10)

	var wg sync.WaitGroup

	for i := 0; i < e.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for line := range plainsChan {
				for _, alg := range algos {
					for _, salt := range salts {
						hash, err := alg.Seal(line, salt)
						if err != nil {
							continue
						}
						resultsChan <- predbRes{
							algo:  alg.Name(),
							hash:  hash,
							salt:  salt,
							plain: line,
						}
					}
				}
			}
		}()
	}

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		files := make(map[string]*os.File)
		writers := make(map[string]*bufio.Writer)
		counts := make(map[string]int)
		for _, alg := range algos {
			algoName := alg.Name()
			if _, ok := writers[algoName]; ok {
				continue
			}
			dbPath := filepath.Join(e.PredbDir, fmt.Sprintf(PredbFileFormat, algoName))
			dbObj, err := os.OpenFile(dbPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				logging.Errorf("Failed to open pre-db file for %s: %v", algoName, err)
				continue
			}
			files[algoName] = dbObj
			writers[algoName] = bufio.NewWriterSize(dbObj, 256*1024)
			counts[algoName] = 0
		}
		defer func() {
			for _, w := range writers {
				w.Flush()
			}
			for _, f := range files {
				f.Close()
			}
		}()

		for res := range resultsChan {
			w, ok := writers[res.algo]
			if !ok {
				fname := filepath.Join(e.PredbDir, fmt.Sprintf(PredbFileFormat, res.algo))
				f, err := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					logging.Errorf("Failed to open pre-db file for %s: %v", res.algo, err)
					continue
				}
				files[res.algo] = f
				w = bufio.NewWriterSize(f, 256*1024)
				writers[res.algo] = w
				counts[res.algo] = 0
			}

			// 定义存储密文格式
			element := []string{HashStringFormat(res.hash), res.salt, res.plain}
			entry := strings.Join(element, ConcatSymbol)
			w.WriteString(entry + "\n")
			counts[res.algo]++
			if counts[res.algo]%4096 == 0 {
				w.Flush()
			}
		}
	}()

	count := 0
	startTime := time.Now()
	for _, text := range plains {
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		plainsChan <- text
		count++
		if count%ProgressReportInterval == 0 {
			logging.Infof("Processed %d lines...", count)
		}
	}
	close(plainsChan)

	wg.Wait()
	close(resultsChan)
	<-writerDone

	logging.Infof("Processed %d lines in %v", count, time.Since(startTime))
}
