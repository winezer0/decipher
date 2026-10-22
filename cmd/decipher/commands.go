package main

import "github.com/jessevdk/go-flags"

// Register shared state in the relevant command scopes; rendering stays native.
func registerCommands(parser *flags.Parser, opts *Options) map[string]*Options {
	group := func(command *flags.Command, name string, data interface{}) {
		if _, err := command.AddGroup(name, "", data); err != nil {
			panic(err)
		}
	}
	command := func(parent *flags.Command, name, description string) *flags.Command {
		cmd, err := parent.AddCommand(name, description, description, &struct{}{})
		if err != nil {
			panic(err)
		}
		return cmd
	}
	root := parser.Command
	group(root, "查询", &opts.InfoOptions)
	group(root, "缓存与维护", &opts.MaintenanceOptions)
	group(root, "数据目录", &opts.DirectoryOptions)
	group(root, "失败记录", &opts.FailureOptions)
	group(root, "日志", &opts.LogOptions)
	enc := command(root, "enc", "计算明文的哈希或密文")
	dec := command(root, "dec", "破解哈希或解密密文")
	id := command(root, "id", "识别哈希算法")
	dict := command(root, "dict", "管理内置字典和预计算库")
	add := command(dict, "add", "追加内置字典， 不生成预计算库")
	init := command(dict, "init", "生成预计算库， 不追加内置字典")
	configs := make(map[*flags.Command]*Options)
	byName := make(map[string]*Options)
	for cmd, name := range map[*flags.Command]string{enc: "enc", dec: "dec", id: "id", add: "dict add", init: "dict init"} {
		config := &Options{}
		config.Output, config.OutputType, config.ConcatSymbol = ".", "csv", ":"
		configs[cmd], byName[name] = config, config
	}
	for _, cmd := range []*flags.Command{enc, dec, init} {
		group(cmd, "算法", &configs[cmd].AlgorithmOptions)
		group(cmd, "明文与盐值修饰", &configs[cmd].AffixOptions)
		group(cmd, "性能", &configs[cmd].WorkerOptions)
	}
	for _, cmd := range []*flags.Command{enc, dec, add, init} {
		group(cmd, "明文字典", &configs[cmd].PlainOptions)
		group(cmd, "盐值与密钥", &configs[cmd].SecretOptions)
	}
	for _, cmd := range []*flags.Command{dec, id} {
		group(cmd, "目标", &configs[cmd].HashOptions)
	}
	group(dec, "哈希格式", &configs[dec].SeparatorOptions)
	group(dec, "破解控制", &configs[dec].CrackOptions)
	for _, cmd := range []*flags.Command{enc, dec, id} {
		group(cmd, "输出", &configs[cmd].ResultOptions)
	}
	for _, cmd := range []*flags.Command{enc, dec, id, add, init} {
		group(cmd, "临时文件", &configs[cmd].TemporaryOptions)
	}
	return byName
}
