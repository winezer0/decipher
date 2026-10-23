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
	group(root, "Information", &opts.InfoOptions)
	group(root, "Cache and maintenance", &opts.MaintenanceOptions)
	group(root, "Data directories", &opts.DirectoryOptions)
	group(root, "Failure records", &opts.FailureOptions)
	group(root, "Logging", &opts.LogOptions)
	enc := command(root, "enc", "Hash plaintext or encrypt data")
	dec := command(root, "dec", "Crack hashes or decrypt ciphertext")
	id := command(root, "id", "Identify hash algorithms")
	add := command(root, "dict-add", "Append words to built-in dictionaries")
	init := command(root, "predb-init", "Build the precomputed database")
	configs := make(map[*flags.Command]*Options)
	byName := make(map[string]*Options)
	for cmd, name := range map[*flags.Command]string{enc: "enc", dec: "dec", id: "id", add: "dict-add", init: "predb-init"} {
		config := &Options{}
		config.Output, config.OutputType, config.ConcatSymbol = ".", "csv", ":"
		configs[cmd], byName[name] = config, config
	}
	for _, cmd := range []*flags.Command{enc, dec, init} {
		group(cmd, "Algorithms", &configs[cmd].AlgorithmOptions)
		group(cmd, "Plaintext and salt modifiers", &configs[cmd].AffixOptions)
		group(cmd, "Performance", &configs[cmd].WorkerOptions)
	}
	for _, cmd := range []*flags.Command{enc, dec, add, init} {
		group(cmd, "Plaintext dictionaries", &configs[cmd].PlainOptions)
		group(cmd, "Salts and keys", &configs[cmd].SecretOptions)
	}
	for _, cmd := range []*flags.Command{dec, id} {
		group(cmd, "Targets", &configs[cmd].HashOptions)
	}
	group(dec, "Hash format", &configs[dec].SeparatorOptions)
	group(dec, "Cracking options", &configs[dec].CrackOptions)
	for _, cmd := range []*flags.Command{enc, dec, id} {
		group(cmd, "Output", &configs[cmd].ResultOptions)
	}
	for _, cmd := range []*flags.Command{enc, dec, id, add, init} {
		group(cmd, "Temporary files", &configs[cmd].TemporaryOptions)
	}
	return byName
}
