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
	"github.com/winezer0/xutils/logging"
	"github.com/winezer0/xutils/utils"
)

const (
	AppName      = "decipher"
	AppVersion   = "0.1.2"
	BuildDate    = "2026-04-27"
	AppShortDesc = "常见哈希快速破解工具"
	AppLongDesc  = "支持哈希识别、加密、字典破解及预计算数据库管理。"
)

// Options 命令行参数结构体
type Options struct {
	Command       string
	ActionOptions `group:"操作与算法"`
	InputOptions  `group:"输入与字典"`
	AffixOptions  `group:"明文与盐值修饰"`
	WorkerOptions `group:"性能"`
	OutputOptions `group:"输出"`
	CacheOptions  `group:"缓存与维护"`
	LogOptions    `group:"日志"`
}

type ActionOptions struct {
	AlgorithmOptions
	InfoOptions
}

type AlgorithmOptions struct {
	AlgoKeys     []string `short:"a" long:"algos" value-name:"STRINGS" description:"算法筛选关键词， 例如 md5； 未指定时选择全部"`
	AlgosPrecise bool     `short:"A" long:"precise" description:"按算法名称精确匹配"`
}

type InfoOptions struct {
	ListAlgos bool `short:"L" long:"list" description:"列出所有可用算法并退出"`
	Version   bool `short:"v" long:"version" description:"显示程序版本并退出"`
}

type InputOptions struct {
	HashOptions
	PlainOptions
	SecretOptions
	SeparatorOptions
}
type HashOptions struct {
	Hashes []string `short:"i" long:"hashes" value-name:"STRINGS" description:"哈希、密文或文件； 支持 file:/str:/gen:"`
}
type PlainOptions struct {
	UsedPlains []string `short:"p" long:"plains" value-name:"STRINGS" description:"明文或候选字典； - 表示内置字典"`
}
type SecretOptions struct {
	UsedSecrets []string `short:"s" long:"secrets" value-name:"STRINGS" description:"盐值、密钥或字典； - 表示内置盐字典"`
}
type SeparatorOptions struct {
	ConcatSymbol string `long:"concat-symbol" value-name:"STRING" description:"哈希各部分的分隔符" default:":"`
}

type AffixOptions struct {
	SaltPrefix string `long:"sp" value-name:"STRING" description:"盐值前缀" default:""`
	SaltSuffix string `long:"ss" value-name:"STRING" description:"盐值后缀" default:""`
	PassPrefix string `long:"pp" value-name:"STRING" description:"明文前缀" default:""`
	PassSuffix string `long:"ps" value-name:"STRING" description:"明文后缀" default:""`
}

type WorkerOptions struct {
	Workers int `short:"w" long:"workers" value-name:"INT" description:"并发工作数； 0 表示按 CPU 数量设置" default:"0"`
}

type OutputOptions struct {
	ResultOptions
	FailureOptions
}
type ResultOptions struct {
	Output     string `short:"o" long:"output" value-name:"PATH" description:"输出目录； 同名结果文件默认覆盖" default:"."`
	OutputType string `short:"O" long:"output-type" value-name:"STRING" description:"输出格式： csv 或 json" choice:"csv" choice:"json" default:"csv"`
}
type FailureOptions struct {
	FailureCache string `long:"failure-cache" value-name:"PATH" description:"失败记录文件名， 相对于输出目录" default:"decipher.failure.csv"`
}

type CacheOptions struct {
	MaintenanceOptions
	TemporaryOptions
	CrackOptions
	DirectoryOptions
}
type MaintenanceOptions struct {
	DedupPredb bool `short:"D" long:"dc" description:"预计算库文件去重， 完成后退出"`
	ClearCache bool `short:"C" long:"cc" description:"清空预计算库、 缓存及失败记录后退出"`
}
type TemporaryOptions struct {
	RemoveTemp bool `short:"R" long:"rr" description:"成功或失败后， 清理本次临时字典"`
}
type CrackOptions struct {
	NoPredbCrack bool `long:"npc" description:"禁用预计算库查询， 改为现场计算"`
	NoDynaCrack  bool `long:"ndc" description:"跳过动态哈希破解"`
	NohashCache  bool `long:"nhc" description:"禁用计算缓存； 不影响成功结果缓存"`
}
type DirectoryOptions struct {
	PredbDir    string `long:"predb-dir" value-name:"PATH" description:"预计算库、 内置字典的目录" default:"decipher_db"`
	RunCacheDir string `long:"run-cache-dir" value-name:"PATH" description:"运行缓存、 临时字典的目录" default:"decipher_cache"`
}

type LogOptions struct {
	LogLevel      string `long:"ll" value-name:"STRING" description:"日志级别： debug/info/warn/error" default:"info"`
	LogFile       string `long:"lf" value-name:"PATH" description:"日志文件路径"`
	ConsoleFormat string `long:"lcf" value-name:"STRING" description:"日志格式： T 时间、 L 级别、 C 位置、 F 函数、 M 消息； 空值或 off 关闭" default:"LM"`
}

const AppInputHelp = `
输入说明：
  file:路径    从文件逐行读取，例如 file:hashes.txt
  str:内容     将内容作为字符串，例如 str:123456
  gen:规则     按规则生成字典，具体规则参见 README
  不带前缀时， 优先读取同名文件； 不存在则作为字符串。
  -p - 和 -s - 使用内置字典，不表示标准输入。
  多个值可重复传入， 或用逗号分隔； 字符串和路径也会被拆分。
  dec 默认使用内置字典； enc 必须通过 -p 提供明文。
  每次运行选择 enc、 dec、 id、 dict add 或 dict init。
  dict add 仅追加内置字典； dict init 仅生成预计算库。
  dict init 未指定 -p/-s 时读取相应内置字典。
  --cc/--dc 可独立执行维护， 完成后退出。
  enc/dec/id 同名结果文件默认覆盖； 失败记录有新数据时覆盖。
  成功缓存、 内置字典和预计算库沿用追加规则。
  显式 file: 文件无效时立即失败， 不回退到内置字典。
  STRINGS 表示字符串列表， STRING 表示字符串， INT 表示整数， PATH 表示路径。

示例：
  查看当前支持算法：		decipher --list
  识别哈希并保存结果：		decipher id -i file:hashes.txt -o .
  计算明文的 MD5：		decipher enc -p str:123456 -a 'md5($pass)' -A
  使用字典破解 MD5：		decipher dec -i file:hashes.txt -p file:words.txt -a 'md5($pass)' -A
  使用内置字典破解：		decipher dec -i file:hashes.txt -p -
  追加内置字典：		decipher dict add -p file:words.txt
  生成预计算库：		decipher dict init -a 'md5($pass)' -A
`

func InitOptionsArgs(minimumParams int) (*Options, *flags.Parser) {
	opts := &Options{}
	opts.Output = "."
	opts.OutputType = "csv"
	opts.ConcatSymbol = ":"
	parser := flags.NewNamedParser(AppName, flags.Default)
	parser.Name = AppName
	parser.Usage = "[选项]"
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
