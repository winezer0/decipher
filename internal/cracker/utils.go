package cracker

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	utils "github.com/winezer0/xutils/pathutils"
	logging "github.com/winezer0/zaplogs"
)

func ParseFilesToTargets(hashesFiles []string) []HashSaltTarget {
	return readDictionaryFiles(hashesFiles, func(line string) (HashSaltTarget, bool) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			return HashSaltTarget{}, false
		}
		separator := ConcatSymbol
		if !strings.Contains(line, separator) {
			separator = ":"
		}
		if separator == "" {
			// 空分隔符保留 strings.Split 按 UTF-8 序列拆分的原有语义。
			hash, salt, _, _ := ParseHashLine(line, separator)
			return HashSaltTarget{Hash: hash, Salt: salt}, hash != ""
		}
		hash, rest, hasSalt := strings.Cut(line, separator)
		if hash == "" {
			return HashSaltTarget{}, false
		}
		var salt string
		if hasSalt {
			var tail string
			salt, tail, _ = strings.Cut(rest, separator)
			// 大块的多余字段不应被 hash/salt 子串长期保留；短行避免额外复制。
			if len(tail) > len(hash)+len(salt) {
				prefix := strings.Clone(line[:len(hash)+len(separator)+len(salt)])
				hash, salt = prefix[:len(hash)], prefix[len(hash)+len(separator):]
			}
		}
		return HashSaltTarget{Hash: hash, Salt: salt}, true
	})
}

// ReadFilesToStrings 返回字符串的列表
func ReadFilesToStrings(inputs []string, trims bool) []string {
	return readDictionaryFiles(inputs, func(line string) (string, bool) {
		if trims {
			line = strings.TrimSpace(line)
		}
		return line, line != ""
	})
}

// 该上限与原 xutils.ReadFileToList 一致，独立于破解任务的 1 MB 行长上限。
const maxDictionaryTokenSize = 10 * 1024 * 1024

// readDictionaryFiles 直接收集最终类型，避免每个文件的中间字符串列表。
func readDictionaryFiles[T any](inputs []string, parse func(string) (T, bool)) []T {
	var values []T
	for _, path := range inputs {
		if !utils.FileExists(path) {
			logging.Warnf("file is not exists: %s", path)
			continue
		}
		checkpoint := values
		err := readDictionaryFile(path, func(line string) {
			if value, ok := parse(line); ok {
				values = append(values, value)
			}
		})
		if err != nil {
			// 原接口丢弃失败文件的全部内容；同时清除尾部引用并保留 nil 语义。
			clear(values[len(checkpoint):])
			clear(checkpoint[len(checkpoint):cap(checkpoint)])
			values = checkpoint
			logging.Warnf("file is load error: %s: %v", path, err)
		}
	}
	return values
}

func readDictionaryFile(path string, emit func(string)) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return scanDictionaryLines(file, emit)
}

func scanDictionaryLines(reader io.Reader, emit func(string)) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, DefaultScannerBufferSize), maxDictionaryTokenSize)
	for scanner.Scan() {
		// 先在扫描缓冲区裁剪，避免为行两端的大量空白分配字符串。
		line := cleanDictionaryLine(string(bytes.TrimSpace(scanner.Bytes())))
		if line != "" {
			emit(line)
		}
	}
	return scanner.Err()
}

func cleanDictionaryLine(line string) string {
	// 保持 xutils.CleanupUnprintableChars 的范围；干净字符串直接复用原值。
	// strings.Map 同时保留原实现将无效 UTF-8 转换为 U+FFFD 的行为。
	return strings.Map(func(r rune) rune {
		if r <= 0x001f || (r >= 0x007f && r <= 0x009f) || (r >= 0x2000 && r <= 0x200f) {
			return -1
		}
		return r
	}, line)
}

func ParseHashLine(line, concatSymbol string) (string, string, string, error) {
	if len(strings.TrimSpace(line)) == 0 {
		return "", "", "", fmt.Errorf("empty hash line: %s", line)
	}
	if concatSymbol == "" {
		parts := strings.Split(line, concatSymbol)
		var fields [3]string
		copy(fields[:], parts)
		return fields[0], fields[1], fields[2], nil
	}
	hash, rest, hasSalt := strings.Cut(line, concatSymbol)
	if !hasSalt {
		return hash, "", "", nil
	}
	salt, rest, hasPlain := strings.Cut(rest, concatSymbol)
	if !hasPlain {
		return hash, salt, "", nil
	}
	plain, _, _ := strings.Cut(rest, concatSymbol)
	return hash, salt, plain, nil
}
