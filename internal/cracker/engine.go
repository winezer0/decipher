package cracker

import (
	"decipher/internal/algo"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/winezer0/xutils/logging"
	"github.com/winezer0/xutils/utils"
)

const (
	DefaultScannerBufferSize = 64 * 1024
	MaxScannerTokenSize      = 1024 * 1024
	ProgressReportInterval   = 100000
)

type Engine struct {
	workers  int
	CacheDir string
	mu       sync.Mutex
}

func NewEngine(workers int, cacheDir string) *Engine {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	return &Engine{
		workers:  workers,
		CacheDir: cacheDir,
	}
}

// GetAlgoCacheFilePath 获取算法对应的缓存文件路径
func (e *Engine) GetAlgoCacheFilePath(alg algo.Algorithm) string {
	return filepath.Join(e.CacheDir, fmt.Sprintf("cache_%s.cache", alg.Name()))
}

func (e *Engine) IsEmptyCacheDir() bool {
	entries, err := os.ReadDir(e.CacheDir)
	if err != nil {
		return true
	}

	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".cache") {
			return false
		}
	}

	return true
}

// InitCacheDB 检查并初始化预计算hash缓存
func (e *Engine) InitCacheDB(preDbAlgos []algo.Algorithm, useDicts []string, useSecrets []string) error {
	if e.IsEmptyCacheDir() {
		logging.Warnf("cache dir %s is empty, generating cachedb %s ...", e, algo.GetAlgorithmNames(preDbAlgos))
		e.GenCacheDB(preDbAlgos, useDicts, useSecrets)
	} else {
		for _, alg := range preDbAlgos {
			cacheFile := e.GetAlgoCacheFilePath(alg)
			if !utils.FileExists(cacheFile) {
				logging.Warnf("cachedb for %s not found, generating ...", alg.Name())
				e.GenCacheDB([]algo.Algorithm{alg}, useDicts, useSecrets)
			}
		}
	}
	return nil
}
