package cracker

import (
	"github.com/winezer0/xutils/logging"
	"github.com/winezer0/xutils/utils"
	"os"
	"path/filepath"
	"strings"
)

// HashStringFormat 标准化hash计算结果
func HashStringFormat(line string) string {
	return strings.ReplaceAll(strings.ToLower(line), "-", "")
}

func DeduplicateCache(cacheDir string) {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		logging.Errorf("Failed to read cache directory: %v", err)
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), PredbSuffix) {
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

// getAlgoNameFromCacheFile 从缓存文件名中获取对应的算法名称
func getAlgoNameFromCacheFile(cacheFile os.DirEntry) string {
	cacheFileName := cacheFile.Name()

	// 1. 去除前缀 (例如: "cache_" -> "")
	// 如果文件名不以该前缀开头，TrimPrefix 会原样返回，不会出错
	algoName := strings.TrimPrefix(cacheFileName, PredbPrefix)

	// 2. 去除后缀
	// 原逻辑尝试了三种情况，我们保留这种兼容性以应对可能的文件名变体：
	// 情况 A: 标准格式，带点号 (例如: ".predb")
	// 构造后缀字符串: "." + PredbSuffix
	suffixWithDot := "." + PredbSuffix
	if strings.HasSuffix(algoName, suffixWithDot) {
		algoName = strings.TrimSuffix(algoName, suffixWithDot)
	} else if strings.HasSuffix(algoName, PredbSuffix) {
		// 情况 B: 不带点号 (例如: "predb")
		algoName = strings.TrimSuffix(algoName, PredbSuffix)
	} else if strings.HasSuffix(algoName, ".") {
		// 情况 C: 仅剩一个点号 (极端情况清理)
		algoName = strings.TrimSuffix(algoName, ".")
	}
	return algoName
}
