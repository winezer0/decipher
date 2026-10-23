package cracker

import (
	"strings"

	utils "github.com/winezer0/xutils/pathutils"
	logging "github.com/winezer0/zaplogs"
)

// InitSaltProviders 根据输入的字符串初始化 SaltProvider 列表
func InitSaltProviders(inputs []string) []SaltProvider {
	var providers []SaltProvider

	// 如果没有输入，使用内置
	if len(inputs) == 0 {
		providers = append(providers, NewMemorySaltProvider([]string{""}, "empty"))
		return providers
	}

	for _, input := range inputs {
		if utils.FileExists(input) {
			providers = append(providers, NewFileSaltProvider(input))
		} else if strings.HasPrefix(input, "gen:") {
			p, err := NewGeneratorSaltProvider(input)
			if err != nil {
				logging.Warnf("Failed to init salt generator %s: %v", input, err)
				continue
			}
			providers = append(providers, p)
		} else {
			// 视为单个字符串
			providers = append(providers, NewMemorySaltProvider([]string{input}, "DirectString"))
		}
	}

	// 添加一个空salt情况
	providers = append(providers, NewMemorySaltProvider([]string{""}, "empty"))
	return providers
}

// InitValueSaltProviders creates salt providers from literal in-memory values.
func InitValueSaltProviders(values []string) []SaltProvider {
	if len(values) == 0 {
		return []SaltProvider{NewMemorySaltProvider([]string{""}, "empty")}
	}
	return []SaltProvider{NewMemorySaltProvider(append([]string(nil), values...), "SDK values")}
}
