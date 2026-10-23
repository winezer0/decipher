package main

import (
	"bufio"
	"context"
	"github.com/winezer0/decipher/internal/cracker"
	"errors"
	"fmt"
	"os"
	"strings"

	utils "github.com/winezer0/xutils/pathutils"
	logging "github.com/winezer0/zaplogs"
)

func resolveDictsPrefix(inputs []string, tempdir, dictType string) ([]string, []string, error) {
	var finalPaths []string
	var tempFiles []string

	for _, input := range inputs {
		switch {
		case strings.HasPrefix(input, "file:"):
			path := strings.TrimPrefix(input, "file:")
			if err := validateInputFile(path); err != nil {
				return nil, tempFiles, err
			}
			finalPaths = append(finalPaths, path)

		case strings.HasPrefix(input, "gen:"):
			rule := input
			tmpPath, err := CreateTempFileByGenRule(rule, tempdir, dictType)
			if tmpPath != "" {
				tempFiles = append(tempFiles, tmpPath)
			}
			if err != nil {
				return nil, tempFiles, err
			}
			finalPaths = append(finalPaths, tmpPath)

		case strings.HasPrefix(input, "str:"):
			content := strings.TrimPrefix(input, "str:")
			tmp, err := CreateTempFileByContent(tempdir, content, dictType)
			if tmp != "" {
				tempFiles = append(tempFiles, tmp)
			}
			if err != nil {
				return nil, tempFiles, err
			}
			finalPaths = append(finalPaths, tmp)

		default:
			if utils.FileExists(input) {
				if err := validateInputFile(input); err != nil {
					return nil, tempFiles, err
				}
				finalPaths = append(finalPaths, input)
			} else {
				logging.Warnf("dicts file not exists: %s will as str", input)
				tmp, err := CreateTempFileByContent(tempdir, input, dictType)
				if tmp != "" {
					tempFiles = append(tempFiles, tmp)
				}
				if err != nil {
					return nil, tempFiles, err
				}
				finalPaths = append(finalPaths, tmp)
			}
		}
	}

	return finalPaths, tempFiles, nil
}

func validateInputFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open input file %q: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat input file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("input file %q is not a regular file", path)
	}
	return nil
}

func CreateTempFileByContent(tempdir, content, dictType string) (path string, err error) {
	if err := os.MkdirAll(tempdir, 0755); err != nil {
		return "", err
	}
	tmpFile, err := os.CreateTemp(tempdir, fmt.Sprintf("decipher_temp_%s_*.txt", dictType))
	if err != nil {
		logging.Errorf("create temp file by content error: %v", err)
		return "", err
	}
	path = tmpFile.Name()
	defer func() { err = errors.Join(err, tmpFile.Close()) }()

	if _, err := tmpFile.WriteString(content); err != nil {
		return path, err
	}
	return tmpFile.Name(), nil
}

func CreateTempFileByGenRule(ruleString, tempdir, dictType string) (path string, err error) {
	if err := os.MkdirAll(tempdir, 0755); err != nil {
		return "", err
	}
	normalized, ok := cracker.NormailzeGeneratorRule(ruleString)
	if !ok {
		return "", fmt.Errorf("invalid generator rule: %s", ruleString)
	}

	logging.Infof("normailzed generator rule: %s", normalized)

	provider, err := cracker.NewGeneratorSaltProvider(normalized)
	if err != nil {
		return "", fmt.Errorf("parse generator rule: %w", err)
	}

	tmpFile, err := os.CreateTemp(tempdir, fmt.Sprintf("decipher_gen_%s_*.txt", dictType))
	if err != nil {
		return "", err
	}
	path = tmpFile.Name()
	defer func() { err = errors.Join(err, tmpFile.Close()) }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := bufio.NewWriter(tmpFile)
	for s := range provider.GenerateStream(ctx.Done()) {
		if _, err := w.WriteString(s + "\n"); err != nil {
			return path, err
		}
	}
	if err := w.Flush(); err != nil {
		return path, err
	}

	return tmpFile.Name(), nil
}
