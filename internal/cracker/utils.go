package cracker

import (
	"os"
	"path/filepath"
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

func parseSalts(addSalts []string) ([]string, string) {
	var salts []string
	var saltSigParts []string

	if len(addSalts) > 0 {
		for _, s := range addSalts {
			if info, err := os.Stat(s); err == nil && !info.IsDir() {
				absPath, _ := filepath.Abs(s)
				saltSigParts = append(saltSigParts, "File:"+absPath)
				lines, err := utils.LoadPathOrString(s)
				if err == nil {
					salts = append(salts, lines...)
				}
			} else {
				saltSigParts = append(saltSigParts, "Raw:"+s)
				lines, err := utils.LoadPathOrString(s)
				if err == nil {
					salts = append(salts, lines...)
				}
			}
		}
	}
	if len(salts) == 0 {
		salts = []string{""}
		saltSigParts = append(saltSigParts, "None")
	}
	return salts, strings.Join(saltSigParts, ",")
}

func DeduplicateCache(cacheDir string) {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		logging.Errorf("Failed to read cache directory: %v", err)
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".cache") {
			continue
		}
		path := filepath.Join(cacheDir, entry.Name())
		logging.Infof("Deduplicating %s...", entry.Name())
		if err := utils.DeduplicateFile(path); err != nil {
			logging.Errorf("Failed to deduplicate %s: %v", entry.Name(), err)
		}
	}
	logging.Info("Cache deduplication completed.")
}
