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
	AppVersion   = "0.0.3"
	BuildDate    = "2026-03-02"
	AppShortDesc = "common hash fast cracker"
	AppLongDesc  = "common hash fast cracker"
)

// Options 命令行参数结构体
type Options struct {
	Inputs []string `short:"i" long:"inputs" description:"Input hashes or file containing hashes (one per line)"`

	AlgoKeys []string `short:"a" long:"algos" description:"filter algorithm(s) key to use (e.g. md5)"`
	Workers  int      `short:"w" long:"workers" description:"Number of concurrent workers for cache generation" default:"0"`

	// 字典文件, 用于预计算hash和动态解密，预计算hash相同文件只会计算一次
	DecDicts   []string `short:"d" long:"dec-dicts" description:"custom dicts, will add to pre-db and cracking dynamic hash"`
	DecSecrets []string `short:"s" long:"dec-secrets" description:"custom secrets, will add to pre-db and cracking (hash salts or decrypt keys)" default:"66666"`

	//加密计算字符串hash
	EncryptText []string `long:"et" description:"Text string or file containing text to encrypt"`
	EncryptSalt []string `long:"es" description:"Salt string or file containing salt to encrypt"`

	Output     string `short:"o" long:"output" description:"Output CSV file for decrypted results"`
	OutputType string `short:"O" long:"output-type" description:"Output format: csv or json" default:"csv"`

	ListAlgos bool `short:"L" long:"list" description:"List all available algorithms"`
	ReCache   bool `short:"R" long:"rec" description:"Cleans cache dir all files"`
	DeCache   bool `short:"D" long:"dec" description:"Deduplicate all cache files"`
	Version   bool `short:"v" long:"version" description:"display the program version and exit"`

	DataDir string `long:"data-dir" description:"Dir for store hash db files" default:"~/.decipher"`

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

	// 工具信息存储目录
	opts.DataDir = utils.ReplaceUserHome(opts.DataDir)
	if err := utils.EnsureDir(opts.DataDir, false); err != nil {
		logging.Fatalf("Error init tools data dir%s: %v", opts.DataDir, err)
	}
	logging.Debugf("Tool %s Data Dir: %s", AppName, opts.DataDir)

	// 如果开启了 ReCache，清空缓存目录中的数据
	if opts.ReCache {
		logging.Infof("cleaning up cache dir : %s", opts.DataDir)
		if err := os.RemoveAll(opts.DataDir); err != nil {
			logging.Errorf(" remove cache dir %s error: %v", opts.DataDir, err)
		}
		// Also clean up runcache directory for dynamic cracking
		cacheDir := ".decipher.cache"
		logging.Infof("cleaning up dynamic hash cache dir : %s", cacheDir)
		if err := os.RemoveAll(cacheDir); err != nil {
			logging.Errorf(" remove dynamic hash cache dir %s error: %v", cacheDir, err)
		}

		logging.Infof("cleaning up cache info success : %s, %s", opts.DataDir, cacheDir)
		os.Exit(0)
	}

	// 处理去重 (DeCache)
	if opts.DeCache {
		logging.Infof("deduplicate cache dir files: %s", opts.DataDir)
		cracker.DeduplicateCache(opts.DataDir)
		logging.Infof("deduplicate cache dir files success: %s", opts.DataDir)
		os.Exit(0)
	}

	// 优化结果文件存储路径
	if opts.Output == "" {
		opts.Output = "decipher.results.csv"
	}

	// 处理参数中的逗号
	opts.Inputs = cmdutils.FormatCmdsComma(opts.Inputs)
	opts.DecDicts = cmdutils.FormatCmdsComma(opts.DecDicts)
	opts.DecSecrets = cmdutils.FormatCmdsComma(opts.DecSecrets)
	opts.AlgoKeys = cmdutils.FormatCmdsComma(opts.AlgoKeys)
	opts.DecDicts = cmdutils.FormatCmdsComma(opts.DecDicts)
	opts.EncryptText = cmdutils.FormatCmdsComma(opts.EncryptText)
	opts.EncryptSalt = cmdutils.FormatCmdsComma(opts.EncryptSalt)

	return opts, parser
}
