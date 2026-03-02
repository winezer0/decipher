package main

import (
	"decipher/internal/algo"
	"decipher/internal/cracker"
	"errors"
	"fmt"
	"os"

	"github.com/jessevdk/go-flags"
	"github.com/winezer0/xutils/cmdutils"
	"github.com/winezer0/xutils/logging"
	"github.com/winezer0/xutils/utils"
)

const (
	AppName      = "decipher"
	AppVersion   = "0.0.4"
	BuildDate    = "2026-03-06"
	AppShortDesc = "common hash fast cracker"
	AppLongDesc  = "common hash fast cracker"
)

// Options 命令行参数结构体
type Options struct {
	Inputs []string `short:"i" long:"inputs" description:"Input hashes or file containing hashes (one per line)"`

	// 操作模式 add 添加数据到predb/enc加密/dec解密/
	Mode string `short:"m" long:"mode" description:"action mode" choices:"add,enc,dec" default:"dec"`

	// 字典文件, 用于预计算predb/解密/加密的 明文字典和盐密钥文件，预计算predb时相同文件只会计算一次
	UsedDicts   []string `short:"d" long:"used-dicts" description:"custom dicts, will add to pre-db and cracking dynamic hash"`
	UsedSecrets []string `short:"s" long:"used-secrets" description:"custom secrets, will add to pre-db and cracking (hash salts or decrypt keys)"`
	// 实际使用的算法，为空时使用所有算法
	AlgoKeys []string `short:"a" long:"algos" description:"Keywords used for algos filtering (e.g. md5)"`

	// 性能配置
	Workers int `short:"w" long:"workers" description:"Number of concurrent workers for cache generation" default:"0"`

	// 输出配置
	Output     string `short:"o" long:"output" description:"Output CSV file for decrypted results"`
	OutputType string `short:"O" long:"output-type" description:"Output format" choices:"json,csv" default:"csv"`

	// 其他配置
	ListAlgos  bool `short:"L" long:"list" description:"List all available algorithms"`
	ClearCache bool `short:"C" long:"rec" description:"Cleans cache dir all files"`
	DedupPredb bool `short:"D" long:"dec" description:"Deduplicate all cache files"`

	// NohashCache 禁用哈希缓存，不进行缓存读写
	NohashCache bool `short:"N" long:"no-hash-cache" description:"Disable hash cracking cache"`

	// 缓存目录配置 一般不需要修改
	PredbDir     string `long:"predb-dir" description:"Dir for store hash pre-db files" default:"~/.decipher"`
	RunCacheDir  string `long:"run-cache-dir" description:"Dir for store dynaic hash cache files" default:"decipher_cache"`
	FailureCache string `long:"failure-cache" description:"Hash record with decryption failure" default:"decipher.failure.csv"`

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
	// ClearCache，清空缓存目录中的数据
	if opts.ClearCache {
		logging.Infof("cleaning up cache and db dir: %v", cachePaths)
		utils.ClearPaths(cachePaths, false, 0)
		logging.Infof("cleanup cache and db success: %v", cachePaths)
		os.Exit(0)
	}

	// 处理去重 (DedupPredb)
	if opts.DedupPredb {
		logging.Infof("deduplicate cache dir files: %s", opts.PredbDir)
		cracker.DeduplicateCache(opts.PredbDir)
		logging.Infof("deduplicate cache dir files success: %s", opts.PredbDir)
		os.Exit(0)
	}

	// 优化结果文件存储路径 <AppName>.<Mode>.<OutputType>
	if opts.Output == "" {
		opts.Output = fmt.Sprintf("%s.%s.%s", AppName, opts.Mode, opts.OutputType)
	}

	// 处理参数中的逗号
	opts.Inputs = cmdutils.FormatCmdsComma(opts.Inputs)
	opts.AlgoKeys = cmdutils.FormatCmdsComma(opts.AlgoKeys)
	opts.UsedDicts = cmdutils.FormatCmdsComma(opts.UsedDicts)
	opts.UsedSecrets = cmdutils.FormatCmdsComma(opts.UsedSecrets)
	return opts, parser
}
