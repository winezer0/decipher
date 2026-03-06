package main

import (
	"bufio"
	"decipher/internal/cracker"
	"fmt"
	"os"
	"strings"

	"github.com/winezer0/xutils/logging"
	"github.com/winezer0/xutils/utils"
)

func resolveDictsPrefix(inputs []string, tempdir, dictType string) ([]string, []string) {
	var finalPaths []string
	var tempFiles []string

	for _, input := range inputs {
		switch {
		case strings.HasPrefix(input, "file:"):
			path := strings.TrimPrefix(input, "file:")
			if utils.FileExists(path) {
				finalPaths = append(finalPaths, path)
			} else {
				logging.Warnf("File not found: %s", path)
			}

		case strings.HasPrefix(input, "gen:"):
			rule := input
			tmpPath := CreateTempFileByGenRule(rule, tempdir, dictType)
			if tmpPath != "" {
				finalPaths = append(finalPaths, tmpPath)
				tempFiles = append(tempFiles, tmpPath)
			} else {
				logging.Warnf("create temp file by gen rule %v error", input)
			}

		case strings.HasPrefix(input, "str:"):
			content := strings.TrimPrefix(input, "str:")
			tmp, err := CreateTempFileByContent(tempdir, content, dictType)
			if err == nil {
				finalPaths = append(finalPaths, tmp)
				tempFiles = append(tempFiles, tmp)
			} else {
				logging.Warnf("create temp file by content error: %v", err)
			}

		default:
			if utils.FileExists(input) {
				finalPaths = append(finalPaths, input)
			} else {
				logging.Warnf("dicts file not exists: %s will as str", input)
				tmp, err := CreateTempFileByContent(tempdir, input, dictType)
				if err == nil {
					finalPaths = append(finalPaths, tmp)
					tempFiles = append(tempFiles, tmp)
				} else {
					logging.Warnf("create temp file by content error: %v", err)
				}
			}
		}
	}

	return finalPaths, tempFiles
}

func CreateTempFileByContent(tempdir, content, dictType string) (string, error) {
	utils.EnsureDir(tempdir, false)
	tmpFile, err := os.CreateTemp(tempdir, fmt.Sprintf("decipher_temp_%s_*.txt", dictType))
	if err != nil {
		logging.Errorf("create temp file by content error: %v", err)
		return "", err
	}
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(content); err != nil {
		return "", err
	}
	return tmpFile.Name(), nil
}

func CreateTempFileByGenRule(ruleString, tempdir, dictType string) string {
	utils.EnsureDir(tempdir, false)
	normalized, ok := cracker.NormailzeGeneratorRule(ruleString)
	if !ok {
		return ""
	}

	logging.Infof("normailzed generator rule: %s", normalized)

	provider, err := cracker.NewGeneratorSaltProvider(normalized)
	if err != nil {
		return ""
	}

	tmpFile, err := os.CreateTemp(tempdir, fmt.Sprintf("decipher_gen_%s_*.txt", dictType))
	if err != nil {
		return ""
	}
	defer tmpFile.Close()

	w := bufio.NewWriter(tmpFile)
	for s := range provider.GenerateStream(nil) {
		_, _ = w.WriteString(s + "\n")
	}
	_ = w.Flush()

	return tmpFile.Name()
}
