package cracker

import (
	"bufio"
	"context"
	"decipher/internal/algo/types"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"decipher/internal/algo"

	"github.com/winezer0/xutils/logging"
)

func (e *Engine) loacalPreDBCrack(ctx context.Context, targets []Target, dict io.Reader, results chan<- CrackerResult, algoName string, algoType types.AlgoType) {
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
					AlgoType:  string(algoType),
					Plaintext: plain,
					Salt:      salt,
				}:
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		logging.Errorf("Scanner error in loacalPreDBCrack: %v", err)
	}
}

func (e *Engine) GenCacheDB(selectAlgos []algo.Algorithm, addDicts []string, addSalts []string) {
	logging.Info("Processing Cache Generation...")
	// 如果没有指定任何算法列表，使用所有需要预计算的算法
	if len(selectAlgos) == 0 {
		selectAlgos = algo.GetAllAlgorithms()
	}
	// 过滤出运行预计算hash的算法
	predbAlgos := algo.FilterNeedsPrecomputAlgos(selectAlgos)
	if len(predbAlgos) == 0 {
		logging.Warn("No algorithms that need precomputation to generate cache for.")
		return
	}

	//初始化缓存目录
	if err := os.MkdirAll(e.CacheDir, 0755); err != nil {
		logging.Errorf("Failed to create cache directory %s: %v", e.CacheDir, err)
		return
	}

	//过滤已记录生成的dict
	addedLogPath := filepath.Join(e.CacheDir, "added.log")
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
	salts, saltSignature := parseSalts(addSalts)
	tasks := buildDictTasks(addDicts)
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

		genCacheDBConcurrency(scanner, predbAlgos, salts, e.workers, e.CacheDir)

		if file != nil {
			file.Close()
		}

		if _, err := addedLogFile.WriteString(dedupKey + "\n"); err != nil {
			logging.Errorf("Failed to write to added.log: %v", err)
		}
	}
}
