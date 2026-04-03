package main

import (
	"decipher/internal/algo"
	"decipher/internal/cracker"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jessevdk/go-flags"
	"github.com/winezer0/xutils/cmdutils"
	"github.com/winezer0/xutils/logging"
	"github.com/winezer0/xutils/utils"
)

const (
	AppName      = "decipher"
	AppVersion   = "0.0.8"
	BuildDate    = "2026-04-03"
	AppShortDesc = "common hash fast cracker"
	AppLongDesc  = "common hash fast cracker"
)

// Options 命令行参数结构体
type Options struct {
	Hashes []string `short:"i" long:"hashes" description:"hashes str or hashes files (input also allowed prefix file/str/gen)"`

	// 操作模式 add 添加数据到predb/enc加密/dec解密/
	Mode []string `short:"m" long:"mode" description:"action mode" choices:"add,enc,dec,id" default:"dec"`

	// 字典文件, 用于预计算predb/解密/加密的 明文字典和盐密钥文件，预计算predb时相同文件只会计算一次
	UsedPlains  []string `short:"p" long:"plains" description:"plains dict for selected actions (input also allowed prefix file/str/gen)"`
	UsedSecrets []string `short:"s" long:"secrets" description:"secrets dict for selected actions (input also allowed prefix file/str/gen)"`
	SaltPrefix  string   `long:"sp" description:"Prefix to be prepended to salt before use" default:""`
	SaltSuffix  string   `long:"ss" description:"Suffix to be appended to salt before use" default:""`
	PassPrefix  string   `long:"pp" description:"Prefix to be prepended to passwd before use" default:""`
	PassSuffix  string   `long:"ps" description:"Suffix to be appended to passwd before use" default:""`

	// 实际使用的算法，为空时使用所有算法
	AlgoKeys []string `short:"a" long:"algos" description:"Keywords used for algos filtering (e.g. md5)"`

	// 性能配置
	Workers int `short:"w" long:"workers" description:"Number of concurrent workers for cache generation" default:"0"`

	// 输出配置
	Output     string `short:"o" long:"output" description:"Output directory for decrypted results" default:"."`
	OutputType string `short:"O" long:"output-type" description:"Output format" choices:"json,csv" default:"csv"`

	// 其他配置
	ListAlgos  bool `short:"L" long:"list" description:"List all available algorithms"`
	DedupPredb bool `short:"D" long:"dc" description:"Deduplicate all cache files"`
	ClearCache bool `short:"C" long:"cc" description:"Cleans cache dir all files"`
	RemoveTemp bool `short:"R" long:"rr" description:"Cleans dict str gen temp files"`

	// 不使用本地缓存数据库进行破解
	NoPredbCrack bool `long:"npc" description:"Disable hash cracking by predb found"`
	NoDynaCrack  bool `long:"ndc" description:"Disable hash cracking by dynamic calc"`
	// NohashCache 禁用哈希缓存，不进行缓存读写
	NohashCache bool `long:"nhc" description:"Disable hash cracking cache"`

	// 缓存目录配置 一般不需要修改
	PredbDir     string `long:"predb-dir" description:"Dir for store hash pre-db files" default:"decipher_db"`
	RunCacheDir  string `long:"run-cache-dir" description:"Dir for store dynaic hash cache files" default:"decipher_cache"`
	FailureCache string `long:"failure-cache" description:"Hash record with decryption failure" default:"decipher.failure.csv"`
	ConcatSymbol string `long:"concat-symbol" description:"Symbol for concat hash parts" default:":"`

	Version       bool   `short:"v" long:"version" description:"display the program version and exit"`
	LogLevel      string `long:"ll" description:"Log level (debug, info, warn, error)" default:"info"`
	LogFile       string `long:"lf" description:"Log file path"`
	ConsoleFormat string `long:"lcf" description:"console log format, Choices T(time)/L(level)/C(caller)/F(func)/M(msg), or empty/off" default:"LM"`
}

func InitOptionsArgs(minimumParams int) (*Options, *flags.Parser) {
	opts := &Options{}
	parser := flags.NewParser(opts, flags.Default)
	parser.Name = AppName
	parser.Usage = "[OPTIONS]"
	parser.ShortDescription = AppShortDesc
	parser.LongDescription = AppLongDesc

	if minimumParams > 0 && len(os.Args)-1 < minimumParams {
		parser.WriteHelp(os.Stdout)
		os.Exit(0)
	}

	if _, err := parser.Parse(); err != nil {
		var flagsErr *flags.Error
		if errors.As(err, &flagsErr) && errors.Is(flagsErr.Type, flags.ErrHelp) {
			os.Exit(0)
		}
		fmt.Printf("Error:%v\n", err)
		os.Exit(1)
	}

	// 输出版本信息
	if opts.Version {
		fmt.Printf("%s version %s\n", AppName, AppVersion)
		fmt.Printf("Build Date: %s\n", BuildDate)
		os.Exit(0)
	}

	// 初始化日志记录起
	logCfg := logging.NewLogConfig(opts.LogLevel, opts.LogFile, opts.ConsoleFormat)
	if err := logging.InitLogger(logCfg); err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logging.Sync()

	// 列出当前所有已经实现的加密算法
	if opts.ListAlgos {
		fmt.Println("Available algorithms:")
		for i, a := range algo.GetAllAlgorithms() {
			fmt.Printf("  %d:  %s\n", i+1, a.Name())
		}
		os.Exit(0)
	}

	// 循环处理：替换用户目录
	opts.PredbDir = utils.ReplaceUserHome(opts.PredbDir)
	opts.RunCacheDir = utils.ReplaceUserHome(opts.RunCacheDir)
	opts.FailureCache = utils.ReplaceUserHome(opts.FailureCache)
	cachePaths := []string{opts.PredbDir, opts.RunCacheDir, opts.FailureCache}

	logging.Infof("%s data dirs: %v", AppName, cachePaths)
	// RemovePredb，清空目录中的数据
	if opts.ClearCache {
		logging.Infof("cleaning up cache and db dir: %v", cachePaths)
		utils.ClearPaths(cachePaths, false, 0)
		logging.Infof("cleanup cache and db success: %v", cachePaths)
	}

	// 处理去重 (DedupPredb)
	if opts.DedupPredb {
		logging.Infof("deduplicate cache dir files: %s", opts.PredbDir)
		cracker.DeduplicateCache(opts.PredbDir)
		logging.Infof("deduplicate cache dir files success: %s", opts.PredbDir)
	}

	// 初始化连接符
	if opts.ConcatSymbol != "" {
		cracker.ConcatSymbol = opts.ConcatSymbol
	}

	// 处理参数中的逗号
	opts.Hashes = cmdutils.FormatCmdsComma(opts.Hashes)
	opts.AlgoKeys = cmdutils.FormatCmdsComma(opts.AlgoKeys)
	opts.UsedPlains = cmdutils.FormatCmdsComma(opts.UsedPlains)
	opts.UsedSecrets = cmdutils.FormatCmdsComma(opts.UsedSecrets)
	opts.Mode = cmdutils.FormatCmdsComma(opts.Mode)

	// 替换其中的-字符串
	// 替换其中的-字符串
	opts.UsedPlains = ReplaceHyphens(opts.UsedPlains, filepath.Join(opts.PredbDir, cracker.BuiltinPlain))
	opts.UsedSecrets = ReplaceHyphens(opts.UsedSecrets, filepath.Join(opts.PredbDir, cracker.BuiltinSalt))

	logging.Infof("Used Mode: %v", opts.Mode)
	logging.Infof("Used Plains: %v", opts.UsedPlains)
	logging.Infof("Used Secrets: %v", opts.UsedSecrets)
	logging.Infof("Hashes Target: %v", opts.Hashes)

	return opts, parser
}

// ReplaceHyphens 遍历字符串切片，将所有等于 "-" 的元素替换为 newString。 该函数会直接修改传入的 slice 内容。
func ReplaceHyphens(dict []string, newString string) []string {
	if len(dict) == 0 {
		return []string{}
	}
	for i, v := range dict {
		if v == "-" {
			dict[i] = newString
		}
	}
	return dict
}
