package cracker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/winezer0/decipher/internal/algo"
	"github.com/winezer0/decipher/internal/embeds"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	utils "github.com/winezer0/xutils/pathutils"
	logging "github.com/winezer0/zaplogs"
)

const (
	DefaultScannerBufferSize = 64 * 1024
	MaxScannerTokenSize      = 1024 * 1024
	ProgressReportInterval   = 100000
	PredbPrefix              = "cache_"
	PredbSuffix              = "predb"
	PredbFileFormat          = "cache_%s.predb"
	AffixScopeDirFormat      = "affix-%s"
	AffixSuccessCacheFormat  = "success_%s.cache"
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
	RunCacheDir string // 临时字典目录
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
	if err := engine.InitBuiltinDicts(); err != nil {
		logging.Errorf("Failed to initialize builtin dictionaries: %v", err)
	}

	return engine
}
func NewEngine(workers int, cacheDir string, runCache string) *Engine {
	return NewEngineWithAffix(workers, cacheDir, runCache, "", "", "", "")
}

// WithAffixes returns an operation-local engine copy with the requested affixes.
func (e *Engine) WithAffixes(passPrefix, passSuffix, saltPrefix, saltSuffix string) *Engine {
	copy := *e
	copy.PassPrefix = passPrefix
	copy.PassSuffix = passSuffix
	copy.SaltPrefix = saltPrefix
	copy.SaltSuffix = saltSuffix
	return &copy
}

// GetAlgoPredbPath 获取算法对应的缓存文件路径
func (e *Engine) GetAlgoPredbPath(alg algo.Algorithm) string {
	return filepath.Join(e.predbScopeDir(), fmt.Sprintf("cache_%s.%s", alg.Name(), PredbSuffix))
}

func (e *Engine) IsEmptyPredbDir() bool {
	entries, err := os.ReadDir(e.predbScopeDir())
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
	if scope := e.affixScope(); scope != "" {
		return filepath.Join(e.PredbDir, fmt.Sprintf(AffixSuccessCacheFormat, scope))
	}
	return filepath.Join(e.PredbDir, SuccessCache)
}

func (e *Engine) predbScopeDir() string {
	scope := e.affixScope()
	if scope == "" {
		return e.PredbDir
	}
	return filepath.Join(e.PredbDir, fmt.Sprintf(AffixScopeDirFormat, scope))
}

// affixScope returns a stable digest for one plaintext and salt affix configuration.
func (e *Engine) affixScope() string {
	values := []string{e.PassPrefix, e.PassSuffix, e.SaltPrefix, e.SaltSuffix}
	if values[0] == "" && values[1] == "" && values[2] == "" && values[3] == "" {
		return ""
	}
	var payload []byte
	for _, value := range values {
		payload = strconv.AppendInt(payload, int64(len(value)), 10)
		payload = append(payload, ':')
		payload = append(payload, value...)
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func (e *Engine) GetBuiltinPlainPath() string {
	return filepath.Join(e.PredbDir, BuiltinPlain)
}

func (e *Engine) GetBuiltinSaltPath() string {
	return filepath.Join(e.PredbDir, BuiltinSalt)
}

func (e *Engine) InitBuiltinDicts() error {
	if !utils.FileExists(e.GetBuiltinPlainPath()) {
		if err := embeds.WriteEmbedToFile(e.GetBuiltinPlainPath(), embeds.GetBuiltinPlainsDict()); err != nil {
			return fmt.Errorf("write builtin plain dict to file %s: %w", e.GetBuiltinPlainPath(), err)
		}
	}

	if !utils.FileExists(e.GetBuiltinSaltPath()) {
		if err := embeds.WriteEmbedToFile(e.GetBuiltinSaltPath(), embeds.GetBuiltinSaltsDict()); err != nil {
			return fmt.Errorf("write builtin salt dict to file %s: %w", e.GetBuiltinSaltPath(), err)
		}
	}
	return nil
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
