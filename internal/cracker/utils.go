package cracker

import (
	"bufio"
	"decipher/internal/embeds"
	"strings"

	"github.com/winezer0/xutils/logging"
	"github.com/winezer0/xutils/utils"
)

func ParseFilesToTargets(inputs []string) []HashSaltTarget {
	var targets []HashSaltTarget
	lines := ParseFilesToStrings(inputs, false)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 允许 hash/hash:salt/hash:salt:xxx 格式常见字符串 但是只取前面两节
		// 允许 hash/hash|salt/hash|salt|xxx 格式自定义字符串 也只取前面两节用于解密
		var parts []string
		if strings.Contains(line, ConcatSymbol) {
			parts = strings.Split(line, ConcatSymbol)
		} else {
			parts = strings.Split(line, ":")
		}
		hash := strings.TrimSpace(parts[0])
		salt := ""
		if len(parts) > 1 {
			salt = strings.TrimSpace(parts[1])
		}
		if hash != "" {
			targets = append(targets, HashSaltTarget{Hash: hash, Salt: salt})
		}
	}
	return targets
}

// ParseFilesToStrings 返回字符串的列表
func ParseFilesToStrings(inputs []string, trims bool) []string {
	var targets []string
	for _, path := range inputs {
		// 加载 Input，可能是文件或字符串
		lines, err := utils.LoadPathOrString(path)
		if err != nil {
			logging.Warnf("Failed to load input %s: %v", path, err)
			continue
		}
		for _, line := range lines {
			if trims {
				line = strings.TrimSpace(line)
			}
			if line != "" {
				targets = append(targets, line)
			}
		}
	}
	return targets
}

// loadBuiltinPlainsEntries 加载内置的明文字典
func loadBuiltinPlainsEntries() []string {
	var entries []string
	reader := embeds.GetBuiltinPlainsDict()
	sc := bufio.NewScanner(reader)
	buf := make([]byte, 0, DefaultScannerBufferSize)
	sc.Buffer(buf, MaxScannerTokenSize)
	for sc.Scan() {
		text := strings.TrimSpace(sc.Text())
		if text != "" {
			entries = append(entries, text)
		}
	}
	if err := sc.Err(); err != nil {
		logging.Errorf("Failed to read builtin plains dict: %v", err)
	}
	return entries
}

// loadBuiltinSaltsEntries 加载内置的salt字典
func loadBuiltinSaltsEntries() []string {
	var entries []string
	reader := embeds.GetBuiltinSaltsDict()
	sc := bufio.NewScanner(reader)
	buf := make([]byte, 0, DefaultScannerBufferSize)
	sc.Buffer(buf, MaxScannerTokenSize)
	for sc.Scan() {
		text := strings.TrimSpace(sc.Text())
		if text != "" {
			entries = append(entries, text)
		}
	}
	if err := sc.Err(); err != nil {
		logging.Errorf("Failed to read builtin salts dict: %v", err)
	}
	return entries
}
