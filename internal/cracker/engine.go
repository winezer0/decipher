package cracker

import (
	"decipher/internal/algo"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/winezer0/xutils/hashutils"

	"github.com/winezer0/xutils/logging"
	"github.com/winezer0/xutils/utils"
)

const (
	DefaultScannerBufferSize = 64 * 1024
	MaxScannerTokenSize      = 1024 * 1024
	ProgressReportInterval   = 100000
	PredbPrefix              = "cache_"
	PredbSuffix              = "predb"
	PredbFileFormat          = "cache_%s.predb"
	SuccessCache             = "success.cache"
	ConcatSymbol             = ":" // 设置hash信息之间的链接字符串
)

type Engine struct {
	workers     int
	PredbDir    string // predb目录
	RunCacheDir string // hash计算和解密的缓存目录
}

func NewEngine(workers int, cacheDir string, runCache string) *Engine {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	return &Engine{
		workers:     workers,
		PredbDir:    cacheDir,
		RunCacheDir: runCache,
	}
}

// GetAlgoCacheFilePath 获取算法对应的缓存文件路径
func (e *Engine) GetAlgoCacheFilePath(alg algo.Algorithm) string {
	return filepath.Join(e.PredbDir, fmt.Sprintf("cache_%s.%s", alg.Name(), PredbSuffix))
}

func (e *Engine) IsEmptyPredbDir() bool {
	entries, err := os.ReadDir(e.PredbDir)
	if err != nil {
		return true
	}

	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), PredbSuffix) {
			return false
		}
	}

	return true
}

// CreatePredbWithCheck 检查并初始化预计算hash缓存
func (e *Engine) CreatePredbWithCheck(preDbAlgos []algo.Algorithm, useDicts []string, useSecrets []string) error {
	if e.IsEmptyPredbDir() {
		logging.Warnf("cache dir %s is empty, generating cachedb %s ...", e, algo.GetAlgorithmNames(preDbAlgos))
		e.CreatePredb(useDicts, useSecrets, preDbAlgos)
	} else {
		for _, alg := range preDbAlgos {
			cacheFile := e.GetAlgoCacheFilePath(alg)
			if !utils.FileExists(cacheFile) {
				logging.Warnf("cachedb for %s not found, generating ...", alg.Name())
				e.CreatePredb(useDicts, useSecrets, []algo.Algorithm{alg})
			}
		}
	}
	return nil
}

// GetSuccessCachePath 获取程序对应的成功结果缓存记录
func (e *Engine) GetSuccessCachePath() string {
	return filepath.Join(e.PredbDir, SuccessCache)
}

// GetRuntimeCachePath 获取运行时缓存路径
// 该路径用于存储针对特定哈希值和算法组合的缓存信息
// hash: 目标哈希值
// algos: 使用的算法列表
func (e *Engine) GetRuntimeCachePath(hash string, algos []algo.Algorithm) string {
	algosnames := algo.GetAlgorithmNames(algos)
	algosStr := strings.Join(utils.SortSlice(algosnames), "/")
	alogsHash := hashutils.GetStrHash(algosStr)
	name := fmt.Sprintf("%s.%s.cache", hashutils.GetStrHashShort(hash), alogsHash)
	cachePath := filepath.Join(e.RunCacheDir, name)
	return cachePath
}
