package cracker

import (
	"fmt"
	"strings"

	"github.com/winezer0/xutils/logging"
	"github.com/winezer0/xutils/utils"
)

func ParseFilesToTargets(hashesFiles []string) []HashSaltTarget {
	var targets []HashSaltTarget
	lines := ReadFilesToStrings(hashesFiles, false)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var hash, salt string
		var err error
		if strings.Contains(line, ConcatSymbol) {
			// 允许 hash/hash|salt/hash|salt|xxx 格式自定义字符串 也只取前面两节用于解密
			hash, salt, _, err = ParseHashLine(line, ConcatSymbol)
			if err != nil {
				continue
			}
		} else {
			// 允许 hash/hash:salt/hash:salt:xxx 格式常见字符串 但是只取前面两节
			hash, salt, _, err = ParseHashLine(line, ":")
			if err != nil {
				continue
			}
		}
		if hash != "" {
			targets = append(targets, HashSaltTarget{Hash: hash, Salt: salt})
		}
	}
	return targets
}

// ReadFilesToStrings 返回字符串的列表
func ReadFilesToStrings(inputs []string, trims bool) []string {
	var finalLines []string
	for _, path := range inputs {
		// 加载 Input，可能是文件或字符串
		var lines []string
		var err error
		if utils.FileExists(path) {
			lines, err = utils.ReadFileToList(path, true, true)
			if err != nil {
				logging.Warnf("file is load error: %s: %v", path, err)
				continue
			}
		} else {
			logging.Warnf("file is not exists: %s", path)
		}
		for _, line := range lines {
			if trims {
				line = strings.TrimSpace(line)
			}
			if line != "" {
				finalLines = append(finalLines, line)
			}
		}
	}
	return finalLines
}

func ParseHashLine(line, concatSymbol string) (string, string, string, error) {
	parts := strings.Split(line, concatSymbol)
	var hash, salt, plain string
	if len(strings.TrimSpace(line)) == 0 || len(parts) == 0 {
		return "", "", "", fmt.Errorf("empty hash line: %s", line)
	}
	if len(parts) > 0 {
		hash = parts[0]
	}
	if len(parts) > 1 {
		salt = parts[1]
	}
	if len(parts) > 2 {
		plain = parts[2]
	}
	return hash, salt, plain, nil
}
