package cracker

import (
	"strings"

	"github.com/winezer0/xutils/logging"
	"github.com/winezer0/xutils/utils"
)

func ParseStringsToTargets(inputs []string) []Target {
	var targets []Target
	for _, hashStr := range inputs {
		// 加载 Input，可能是文件或字符串
		lines, err := utils.LoadPathOrString(hashStr)
		if err != nil {
			logging.Warnf("Failed to load input %s: %v", hashStr, err)
			continue
		}

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			hash := strings.TrimSpace(parts[0])
			salt := ""
			if len(parts) > 1 {
				salt = strings.TrimSpace(parts[1])
			}
			if hash != "" {
				targets = append(targets, Target{Hash: hash, Salt: salt})
			}
		}
	}
	return targets
}

// HashStringFormat 标准化hash计算结果
func HashStringFormat(line string) string {
	return strings.ReplaceAll(strings.ToLower(line), "-", "")
}
