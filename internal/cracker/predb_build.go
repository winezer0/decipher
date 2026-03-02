package cracker

import (
	"bufio"
	"decipher/internal/algo"
	"decipher/internal/embeds"
	"decipher/internal/myutils"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/winezer0/xutils/logging"
)

type dictTask struct {
	Name       string
	Path       string
	GetScanner func() (*bufio.Scanner, *os.File, error)
}

func buildDictTasks(addDicts []string) []dictTask {
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
	addDicts = myutils.ConvertStringsToFiles(addDicts, "temp.dict")
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

func genCacheDBConcurrency(scanner *bufio.Scanner, algos []algo.Algorithm, salts []string, workers int, cacheDir string) {
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
