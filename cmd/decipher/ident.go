package main

import (
	"decipher/internal/cracker"
	"decipher/internal/export"
	"fmt"
	"github.com/winezer0/xutils/logging"
	"github.com/winezer0/xutils/utils"
	"strings"
)

func identAction(engine *cracker.Engine, opts *Options) error {
	// 将用户输入的目标转为文件
	hashesFiles, hashesTemp := resolveDictsPrefix(opts.Hashes, engine.RunCacheDir, "ident_secret")
	if len(hashesFiles) == 0 {
		return fmt.Errorf("not valid hashes target was parsed :%s", opts.Hashes)
	}

	identResult := engine.RunIdentHash(hashesFiles)
	for _, r := range identResult {
		fmt.Printf("%s -> [%s]\n", r.Hash, strings.Join(r.AlgosNames, ","))
	}

	// 清理缓存文件
	if opts.RemoveTemp {
		utils.ClearFiles(hashesTemp...)
	}

	if strings.ToLower(opts.OutputType) == "json" {
		if err := export.ExportJSON(opts.Output, identResult); err == nil {
			logging.Infof("Ident results exported to %s", opts.Output)
			return nil
		} else {
			return err
		}
	}

	if strings.ToLower(opts.OutputType) == "csv" {
		if err := export.ExportIdentCSV(opts.Output, identResult, true); err == nil {
			logging.Infof("Ident results exported to %s", opts.Output)
			return nil
		} else {
			return err
		}
	}

	return fmt.Errorf("output file type no valid")
}
