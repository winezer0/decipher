package cracker

import (
	"bufio"
	"context"
	"decipher/internal/myutil"
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
	"decipher/internal/embeds"
)

func (e *Engine) crackByPreDB(ctx context.Context, targets []Target, dict io.Reader, results chan<- CrackerResult, algoName string, algoType string) {
	targetMap := make(map[string][]Target)
	for _, t := range targets {
		hash := HashStringFormat(t.Hash)
		targetMap[hash] = append(targetMap[hash], t)
	}

	scanner := bufio.NewScanner(dict)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 3)
		var hash, salt, plain string
		if len(parts) == 3 {
			hash, salt, plain = parts[0], parts[1], parts[2]
		} else if len(parts) == 2 {
			hash, plain = parts[0], parts[1]
			salt = ""
		} else {
			continue
		}

		if matchedTargets, ok := targetMap[hash]; ok {
			for _, t := range matchedTargets {
				select {
				case <-ctx.Done():
					return
				case results <- CrackerResult{
					Hash:      t.Hash,
					Algorithm: algoName,
					AlgoType:  algoType,
					Plaintext: plain,
					Salt:      salt,
				}:
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		logging.Errorf("Scanner error in crackByPreDB: %v", err)
	}
}

func HasCacheFiles(cacheDir string) bool {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".cache") {
			return true
		}
	}
	return false
}

func DeduplicateCache(cacheDir string) {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		logging.Errorf("Failed to read cache directory: %v", err)
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".cache") {
			continue
		}
		path := filepath.Join(cacheDir, entry.Name())
		logging.Infof("Deduplicating %s...", entry.Name())
		if err := utils.DeduplicateFile(path); err != nil {
			logging.Errorf("Failed to deduplicate %s: %v", entry.Name(), err)
		}
	}
	logging.Info("Cache deduplication completed.")
}

func (e *Engine) GenCacheDB(cacheDir string, addDicts []string, addSalts []string, workers int, algorithms []algo.Algorithm) {
	logging.Info("Processing Cache Generation...")

	//初始化缓存目录
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		logging.Errorf("Failed to create cache directory %s: %v", cacheDir, err)
		return
	}

	// 如果没有指定算法列表，使用所有需要预计算的算法
	var precomputAlgos []algo.Algorithm
	if len(algorithms) > 0 {
		precomputAlgos = algo.FilterNeedsPrecomputAlgorithms(algorithms)
	} else {
		precomputAlgos = algo.FilterNeedsPrecomputAlgorithms(algo.GetAllAlgorithms())
	}

	if len(precomputAlgos) == 0 {
		logging.Warn("No algorithms that need precomputation to generate cache for.")
		return
	}
	// 初始化线程数
	if workers <= 0 {
		workers = e.workers
	}
	//过滤已记录生成的dict
	addedLogPath := filepath.Join(cacheDir, "added.log")
	processedKeys := make(map[string]bool)
	if content, err := os.ReadFile(addedLogPath); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l != "" {
				processedKeys[l] = true
			}
		}
	}

	//解析salt信息
	salts, saltSignature := e.parseSalts(addSalts)
	tasks := e.buildDictTasks(addDicts)
	addedLogFile, err := os.OpenFile(addedLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logging.Errorf("Failed to open added.log: %v", err)
		return
	}
	defer addedLogFile.Close()

	for _, task := range tasks {
		dedupKey := fmt.Sprintf("%s|%s", task.Path, saltSignature)
		if processedKeys[dedupKey] {
			logging.Infof("Skipping %s (already processed with these salts)", task.Name)
			continue
		}

		logging.Infof("Processing %s...", task.Name)
		scanner, file, err := task.GetScanner()
		if err != nil {
			logging.Errorf("Failed to open %s: %v", task.Name, err)
			continue
		}

		e.genCacheDBConcurrency(scanner, precomputAlgos, salts, workers, cacheDir)

		if file != nil {
			file.Close()
		}

		if _, err := addedLogFile.WriteString(dedupKey + "\n"); err != nil {
			logging.Errorf("Failed to write to added.log: %v", err)
		}
	}
}

func (e *Engine) parseSalts(addSalts []string) ([]string, string) {
	var salts []string
	var saltSigParts []string

	if len(addSalts) > 0 {
		for _, s := range addSalts {
			if info, err := os.Stat(s); err == nil && !info.IsDir() {
				absPath, _ := filepath.Abs(s)
				saltSigParts = append(saltSigParts, "File:"+absPath)
				lines, err := utils.LoadPathOrString(s)
				if err == nil {
					salts = append(salts, lines...)
				}
			} else {
				saltSigParts = append(saltSigParts, "Raw:"+s)
				lines, err := utils.LoadPathOrString(s)
				if err == nil {
					salts = append(salts, lines...)
				}
			}
		}
	}
	if len(salts) == 0 {
		salts = []string{""}
		saltSigParts = append(saltSigParts, "None")
	}
	return salts, strings.Join(saltSigParts, ",")
}

type dictTask struct {
	Name       string
	Path       string
	GetScanner func() (*bufio.Scanner, *os.File, error)
}

func (e *Engine) buildDictTasks(addDicts []string) []dictTask {
	var tasks []dictTask

	if len(addDicts) == 0 {
		tasks = append(tasks, dictTask{
			Name: "Builtin Dict",
			Path: "BUILTIN",
			GetScanner: func() (*bufio.Scanner, *os.File, error) {
				reader := embeds.GetBuiltinDict()
				scanner := bufio.NewScanner(reader)
				buf := make([]byte, 0, DefaultScannerBufferSize)
				scanner.Buffer(buf, MaxScannerTokenSize)
				return scanner, nil, nil
			},
		})
	}

	// 如果用户输入的是字符串列表，而不是文件列表字典 需要写入到临时文件中 因为后续pre-db使用的是文件路径
	addDicts = myutil.ConvertStringsToFiles(addDicts, "temp.dict")
	for _, d := range addDicts {
		dPath := d
		absPath, _ := filepath.Abs(d)
		tasks = append(tasks, dictTask{
			Name: fmt.Sprintf("Dict %s", d),
			Path: absPath,
			GetScanner: func() (*bufio.Scanner, *os.File, error) {
				f, err := os.Open(dPath)
				if err != nil {
					return nil, nil, err
				}
				scanner := bufio.NewScanner(f)
				buf := make([]byte, 0, DefaultScannerBufferSize)
				scanner.Buffer(buf, MaxScannerTokenSize)
				return scanner, f, nil
			},
		})
	}

	return tasks
}

func (e *Engine) genCacheDBConcurrency(scanner *bufio.Scanner, algos []algo.Algorithm, salts []string, workers int, cacheDir string) {
	linesChan := make(chan string, workers*2)
	resultsChan := make(chan string, workers*10)

	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for line := range linesChan {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				for _, alg := range algos {
					for _, salt := range salts {
						token, err := alg.Seal(line, salt)
						if err != nil {
							continue
						}
						entry := fmt.Sprintf("%s:%s:%s", token, salt, line)
						resultsChan <- fmt.Sprintf("%s|%s", alg.Name(), entry)
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
		defer func() {
			for _, w := range writers {
				w.Flush()
			}
			for _, f := range files {
				f.Close()
			}
		}()

		for res := range resultsChan {
			parts := strings.SplitN(res, "|", 2)
			if len(parts) != 2 {
				continue
			}
			algoName := parts[0]
			entry := parts[1]

			w, ok := writers[algoName]
			if !ok {
				fname := filepath.Join(cacheDir, fmt.Sprintf("cache_%s.cache", algoName))
				f, err := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					logging.Errorf("Failed to open cache file for %s: %v", algoName, err)
					continue
				}
				files[algoName] = f
				w = bufio.NewWriter(f)
				writers[algoName] = w
			}
			w.WriteString(HashStringFormat(entry) + "\n")
		}
	}()

	count := 0
	startTime := time.Now()
	for scanner.Scan() {
		linesChan <- scanner.Text()
		count++
		if count%ProgressReportInterval == 0 {
			logging.Infof("Processed %d lines...", count)
		}
	}
	close(linesChan)

	if err := scanner.Err(); err != nil {
		logging.Errorf("Scanner error in genCacheDBConcurrency: %v", err)
	}

	wg.Wait()
	close(resultsChan)
	<-writerDone

	logging.Infof("Processed %d lines in %v", count, time.Since(startTime))
}
