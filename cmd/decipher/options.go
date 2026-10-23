package main

import (
	"decipher/internal/algo"
	"decipher/internal/cracker"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jessevdk/go-flags"
	"github.com/winezer0/xutils/cmdutils"
	utils "github.com/winezer0/xutils/pathutils"
	logging "github.com/winezer0/zaplogs"
)

const (
	AppName      = "decipher"
	AppVersion   = "0.2.0"
	BuildDate    = "2026-10-23"
	AppShortDesc = "Fast hash recovery tool"
	AppLongDesc  = "Identify hashes, compute hashes and ciphertexts, crack with dictionaries, and manage precomputed databases."
)

// Options 命令行参数结构体
type Options struct {
	Command       string
	ActionOptions `group:"Actions and algorithms"`
	InputOptions  `group:"Input and dictionaries"`
	AffixOptions  `group:"Plaintext and salt modifiers"`
	WorkerOptions `group:"Performance"`
	OutputOptions `group:"Output"`
	CacheOptions  `group:"Cache and maintenance"`
	LogOptions    `group:"Logging"`
}

type ActionOptions struct {
	AlgorithmOptions
	InfoOptions
}

type AlgorithmOptions struct {
	AlgoKeys     []string `short:"a" long:"algos" value-name:"STRINGS" description:"Filter algorithms by keyword (for example, md5); select all when omitted"`
	AlgosPrecise bool     `short:"A" long:"precise" description:"Match algorithm names exactly"`
}

type InfoOptions struct {
	ListAlgos bool `short:"L" long:"list" description:"List all available algorithms and exit"`
	Version   bool `short:"v" long:"version" description:"Show version information and exit"`
}

type InputOptions struct {
	HashOptions
	PlainOptions
	SecretOptions
	SeparatorOptions
}
type HashOptions struct {
	Hashes []string `short:"i" long:"hashes" value-name:"STRINGS" description:"Hashes, ciphertexts, or files; supports file:/str:/gen:"`
}
type PlainOptions struct {
	UsedPlains []string `short:"p" long:"plains" value-name:"STRINGS" description:"Plaintext values or candidate dictionaries; - selects the built-in dictionary"`
}
type SecretOptions struct {
	UsedSecrets []string `short:"s" long:"secrets" value-name:"STRINGS" description:"Salts, keys, or dictionaries; - selects the built-in salt dictionary"`
}
type SeparatorOptions struct {
	ConcatSymbol string `long:"concat-symbol" value-name:"STRING" description:"Separator between hash fields" default:":"`
}

type AffixOptions struct {
	SaltPrefix string `long:"sp" value-name:"STRING" description:"Prefix added to salts" default:""`
	SaltSuffix string `long:"ss" value-name:"STRING" description:"Suffix added to salts" default:""`
	PassPrefix string `long:"pp" value-name:"STRING" description:"Prefix added to plaintext candidates" default:""`
	PassSuffix string `long:"ps" value-name:"STRING" description:"Suffix added to plaintext candidates" default:""`
}

type WorkerOptions struct {
	Workers int `short:"w" long:"workers" value-name:"INT" description:"Number of workers; 0 selects a value based on the CPU count" default:"0"`
}

type OutputOptions struct {
	ResultOptions
	FailureOptions
}
type ResultOptions struct {
	Output     string `short:"o" long:"output" value-name:"PATH" description:"Output directory; same-named result files are overwritten" default:"."`
	OutputType string `short:"O" long:"output-type" value-name:"STRING" description:"Output format: csv or json" choice:"csv" choice:"json" default:"csv"`
}
type FailureOptions struct {
	FailureCache string `long:"failure-cache" value-name:"PATH" description:"Failure-record filename, relative to the output directory" default:"decipher.failure.csv"`
}

type CacheOptions struct {
	MaintenanceOptions
	TemporaryOptions
	CrackOptions
	DirectoryOptions
}
type MaintenanceOptions struct {
	DedupPredb bool `short:"D" long:"dc" description:"Deduplicate precomputed database files and exit"`
	ClearCache bool `short:"C" long:"cc" description:"Clear precomputed databases, caches, and failure records, then exit"`
}
type TemporaryOptions struct {
	RemoveTemp bool `short:"R" long:"rr" description:"Remove temporary dictionaries created by this run after success or failure"`
}
type CrackOptions struct {
	NoPredbCrack bool `long:"npc" description:"Disable precomputed database lookup and use runtime calculation"`
	NoDynaCrack  bool `long:"ndc" description:"Skip dynamic hash cracking"`
}
type DirectoryOptions struct {
	PredbDir    string `long:"predb-dir" value-name:"PATH" description:"Directory for precomputed databases and built-in dictionaries" default:"decipher_db"`
	RunCacheDir string `long:"run-cache-dir" value-name:"PATH" description:"Directory for temporary dictionaries" default:"decipher_cache"`
}

type LogOptions struct {
	LogLevel      string `long:"ll" value-name:"STRING" description:"Log level: debug/info/warn/error" default:"info"`
	LogFile       string `long:"lf" value-name:"PATH" description:"Log file path"`
	ConsoleFormat string `long:"lcf" value-name:"STRING" description:"Console log format: T time, L level, C source, F function, M message; empty or off disables logging" default:"LM"`
}

const AppInputHelp = `Input formats:
  file:PATH    Read lines from a file, for example file:hashes.txt
  str:VALUE    Treat the value as a string, for example str:123456
  gen:RULE     Generate dictionary entries according to a rule (see README)
  Without a prefix, an existing file is read; otherwise the value is treated as a string.
  -p - and -s - select built-in dictionaries; they do not mean standard input.
  Pass multiple values with repeated flags or comma-separated items; commas in strings and paths are split.
  dec uses the built-in dictionary by default; enc requires plaintext via -p.
  Choose one operation per run: enc, dec, id, dict add, or dict init.
  dict add only appends built-in dictionaries; dict init only builds the precomputed database.
  dict init reads the corresponding built-in dictionary when -p/-s is omitted.
  --cc/--dc run maintenance operations independently and exit.
  enc/dec/id overwrite same-named result files; failure records are overwritten when new failures exist.
  Success cache, built-in dictionaries, and precomputed databases follow their existing append behavior.
  An invalid explicit file: input fails immediately and never falls back to a built-in dictionary.
  STRINGS means a list of strings, STRING a string, INT an integer, and PATH a filesystem path.

Examples:
  List available algorithms:        decipher --list
  Identify hashes and save results: decipher id -i file:hashes.txt -o .
  Compute an MD5 hash:              decipher enc -p str:123456 -a 'md5($pass)' -A
  Crack MD5 with a dictionary:      decipher dec -i file:hashes.txt -p file:words.txt -a 'md5($pass)' -A
  Use the built-in dictionary:      decipher dec -i file:hashes.txt -p -
  Append to built-in dictionaries:  decipher dict add -p file:words.txt
  Build the precomputed database:   decipher dict init -a 'md5($pass)' -A
`

func InitOptionsArgs(minimumParams int) (*Options, *flags.Parser) {
	opts := &Options{}
	opts.Output = "."
	opts.OutputType = "csv"
	opts.ConcatSymbol = ":"
	parser := flags.NewNamedParser(AppName, flags.Default)
	parser.Name = AppName
	parser.Usage = "[OPTIONS]"
	parser.ShortDescription = AppShortDesc
	parser.LongDescription = AppLongDesc + "\n" + AppInputHelp
	parser.SubcommandsOptional = true // 根级查询和维护命令无需业务子命令。
	configs := registerCommands(parser, opts)

	if minimumParams > 0 && len(os.Args)-1 < minimumParams {
		_, _ = parser.ParseArgs([]string{"--help"})
		os.Exit(0)
	}

	remaining, err := parser.Parse()
	if err != nil {
		var flagsErr *flags.Error
		if errors.As(err, &flagsErr) && errors.Is(flagsErr.Type, flags.ErrHelp) {
			os.Exit(0)
		}
		fmt.Printf("Error:%v\n", err)
		os.Exit(1)
	}
	if len(remaining) > 0 {
		fmt.Fprintf(os.Stderr, "Error: unexpected arguments: %v\n", remaining)
		os.Exit(1)
	}
	if parser.Active != nil {
		opts.Command = parser.Active.Name
		if parser.Active.Active != nil {
			opts.Command += " " + parser.Active.Active.Name
		}
	}
	if config := configs[opts.Command]; config != nil {
		opts.AlgorithmOptions = config.AlgorithmOptions
		opts.InputOptions = config.InputOptions
		opts.AffixOptions = config.AffixOptions
		opts.WorkerOptions = config.WorkerOptions
		opts.ResultOptions = config.ResultOptions
		opts.TemporaryOptions = config.TemporaryOptions
		opts.CrackOptions = config.CrackOptions
	}

	// 输出版本信息
	if opts.Version {
		fmt.Printf("%s version %s\n", AppName, AppVersion)
		fmt.Printf("Build Date: %s\n", BuildDate)
		os.Exit(0)
	}
	if err := normalizeAndValidateOptions(opts); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// 初始化日志记录起
	logCfg := logging.NewLogConfig(opts.LogLevel, opts.LogFile, opts.ConsoleFormat)
	if err := logging.InitDefaultLogger(logCfg); err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

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
	logging.Infof("%s data dirs: %v", AppName, []string{opts.PredbDir, opts.RunCacheDir, opts.FailureCache})

	// 初始化连接符
	if opts.ConcatSymbol != "" {
		cracker.ConcatSymbol = opts.ConcatSymbol
	}

	// 替换其中的-字符串
	opts.UsedPlains = ReplaceHyphens(opts.UsedPlains, filepath.Join(opts.PredbDir, cracker.BuiltinPlain))
	opts.UsedSecrets = ReplaceHyphens(opts.UsedSecrets, filepath.Join(opts.PredbDir, cracker.BuiltinSalt))

	logging.Infof("Used Command: %s", opts.Command)
	logging.Infof("Used Plains: %v", opts.UsedPlains)
	logging.Infof("Used Secrets: %v", opts.UsedSecrets)
	logging.Infof("Hashes Target: %v", opts.Hashes)

	return opts, parser
}

// 在日志、维护操作和引擎初始化写入文件之前校验用户输入。
func normalizeAndValidateOptions(opts *Options) error {
	if opts.Workers < 0 {
		return fmt.Errorf("workers must be >= 0")
	}
	if opts.Command == "" && !opts.ClearCache && !opts.DedupPredb && !opts.ListAlgos {
		return fmt.Errorf("a subcommand is required: enc, dec, id, dict add or dict init")
	}
	opts.Hashes = cmdutils.FormatCmdsComma(opts.Hashes)
	opts.AlgoKeys = cmdutils.FormatCmdsComma(opts.AlgoKeys)
	opts.UsedPlains = cmdutils.FormatCmdsComma(opts.UsedPlains)
	opts.UsedSecrets = cmdutils.FormatCmdsComma(opts.UsedSecrets)
	if opts.Command == "dict add" && len(opts.UsedPlains) == 0 && len(opts.UsedSecrets) == 0 && !opts.ClearCache && !opts.DedupPredb {
		return fmt.Errorf("dict add requires -p or -s")
	}
	for _, inputs := range [][]string{opts.Hashes, opts.UsedPlains, opts.UsedSecrets} {
		for _, input := range inputs {
			if strings.HasPrefix(input, "file:") {
				if err := validateInputFile(strings.TrimPrefix(input, "file:")); err != nil {
					return err
				}
			}
		}
	}
	return nil
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
