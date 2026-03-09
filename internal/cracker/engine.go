package cracker

import (
	"decipher/internal/algo"
	"decipher/internal/embeds"
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
	BuiltinPlain             = "builtin-plain.txt"
	BuiltinSalt              = "builtin-salt.txt"
)

var (
	ConcatSymbol = ":" // 设置hash信息之间的链接字符串
)

type Engine struct {
	workers     int
	PredbDir    string // predb目录
	RunCacheDir string // hash计算和解密的缓存目录
	PassPrefix  string
	PassSuffix  string
	SaltPrefix  string
	SaltSuffix  string
}

func NewEngineWithAffix(workers int, cacheDir string, runCache string, passPrefix string, passSuffix string, saltPrefix string, saltSuffix string) *Engine {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	engine := &Engine{
		workers:     workers,
		PredbDir:    cacheDir,
		RunCacheDir: runCache,
		PassPrefix:  passPrefix,
		PassSuffix:  passSuffix,
		SaltPrefix:  saltPrefix,
		SaltSuffix:  saltSuffix,
	}

	// 初始化内置文件字典
	engine.InitBuiltinDicts()

	return engine
}
func NewEngine(workers int, cacheDir string, runCache string) *Engine {
	return NewEngineWithAffix(workers, cacheDir, runCache, "", "", "", "")
}

// GetAlgoPredbPath 获取算法对应的缓存文件路径
func (e *Engine) GetAlgoPredbPath(alg algo.Algorithm) string {
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

func (e *Engine) GetBuiltinPlainPath() string {
	return filepath.Join(e.PredbDir, BuiltinPlain)
}

func (e *Engine) GetBuiltinSaltPath() string {
	return filepath.Join(e.PredbDir, BuiltinSalt)
}

func (e *Engine) InitBuiltinDicts() {
	if !utils.FileExists(e.GetBuiltinPlainPath()) {
		if err := embeds.WriteEmbedToFile(e.GetBuiltinPlainPath(), embeds.GetBuiltinPlainsDict()); err != nil {
			logging.Errorf("Failed to write builtin plain dict to file %s error: %v", e.GetBuiltinPlainPath(), err)
		}
	}

	if !utils.FileExists(e.GetBuiltinSaltPath()) {
		if err := embeds.WriteEmbedToFile(e.GetBuiltinSaltPath(), embeds.GetBuiltinSaltsDict()); err != nil {
			logging.Errorf("Failed to write builtin salt dict to file %s error: %v", e.GetBuiltinSaltPath(), err)
		}
	}
}

// AffixPasswd 工具函数 为明文附加前后缀 用于适配一些算法中存在其他固定salt附加值的情况
func (e *Engine) AffixPasswd(passwd string) string {
	if e.PassPrefix == "" && e.PassSuffix == "" {
		return passwd
	}
	return e.PassPrefix + passwd + e.PassSuffix
}

// AffixSalt 工具函数 为明文附加前后缀 用于适配一些算法中存在其他固定salt附加值的情况
func (e *Engine) AffixSalt(salt string) string {
	if e.SaltPrefix == "" && e.SaltSuffix == "" {
		return salt
	}

	return e.SaltPrefix + salt + e.SaltSuffix
}
