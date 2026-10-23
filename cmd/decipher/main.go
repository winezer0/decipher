package main

import (
	"decipher/internal/cracker"
	"errors"
	"fmt"
	"os"

	utils "github.com/winezer0/xutils/fileutils"
	logging "github.com/winezer0/zaplogs"
)

func main() {
	os.Exit(run())
}

func run() int {
	opts, _ := InitOptionsArgs(1)
	defer logging.Sync()
	if err := runActions(opts); err != nil {
		logging.Errorf("%v", err)
		return 1
	}
	return 0
}

func runActions(opts *Options) error {
	// 维护操作不初始化引擎，避免清理后重新创建内置字典。
	if opts.ClearCache || opts.DedupPredb {
		return runMaintenance(opts)
	}
	engine := cracker.NewEngineWithAffix(opts.Workers, opts.PredbDir, opts.RunCacheDir, opts.PassPrefix, opts.PassSuffix, opts.SaltPrefix, opts.SaltSuffix)
	actions := []struct {
		command string
		name    string
		run     func(*cracker.Engine, *Options) error
	}{
		{"dict add", "dict add", dictAddAction},
		{"dict init", "dict init", dictInitAction},
		{"id", "ident", identAction},
		{"enc", "encrypt", encryptAction},
		{"dec", "decrypt", decryptAction},
	}
	for _, action := range actions {
		if opts.Command != action.command {
			continue
		}
		logging.Infof("running command %s", action.command)
		if err := action.run(engine, opts); err != nil {
			return fmt.Errorf("%s failed: %w", action.name, err)
		}
		logging.Infof("%s completed", action.name)
	}
	return nil
}

func runMaintenance(opts *Options) error {
	if opts.ClearCache {
		var paths []string
		for _, path := range []string{opts.PredbDir, opts.RunCacheDir, opts.FailureCache} {
			if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
				continue // 已不存在的缓存无需清理。
			} else if err != nil {
				return fmt.Errorf("inspect cache path %s: %w", path, err)
			}
			paths = append(paths, path)
		}
		logging.Infof("cleaning up cache and db dir: %v", paths)
		if _, errs := utils.ClearPaths(paths, false, 0); len(errs) > 0 {
			return fmt.Errorf("clear cache: %w", errors.Join(errs...))
		}
		logging.Info("cleanup cache and db success")
	}
	if opts.DedupPredb {
		if err := cracker.DeduplicateCache(opts.PredbDir); err != nil {
			return err
		}
	}
	return nil
}
