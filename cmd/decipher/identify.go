package main

import (
	"github.com/winezer0/decipher/internal/cracker"
	"github.com/winezer0/decipher/internal/export"
	"fmt"
	logging "github.com/winezer0/zaplogs"
	"path/filepath"
	"strings"
)

func identAction(engine *cracker.Engine, opts *Options) (err error) {
	temps := tempFiles{remove: opts.RemoveTemp}
	defer temps.cleanup(&err)
	// 将用户输入的目标转为文件
	hashesFiles, _, err := temps.resolve(opts.Hashes, engine.RunCacheDir, "ident_secret")
	if err != nil {
		return err
	}
	if len(hashesFiles) == 0 {
		return fmt.Errorf("not valid hashes target was parsed :%s", opts.Hashes)
	}

	identResult := engine.RunIdentHash(hashesFiles)
	for _, r := range identResult {
		fmt.Printf("%s -> [%s]\n", r.Hash, strings.Join(r.AlgosNames, ","))
	}

	outputFile := filepath.Join(opts.Output, fmt.Sprintf("%s.id.%s", AppName, opts.OutputType))
	if strings.ToLower(opts.OutputType) == "json" {
		if err := export.ExportJSON(outputFile, identResult); err == nil {
			logging.Infof("Ident results exported to %s", outputFile)
			return nil
		} else {
			return err
		}
	}

	if strings.ToLower(opts.OutputType) == "csv" {
		if err := export.ExportIdentCSV(outputFile, identResult, true); err == nil {
			logging.Infof("Ident results exported to %s", outputFile)
			return nil
		} else {
			return err
		}
	}

	return fmt.Errorf("output file type no valid")
}
