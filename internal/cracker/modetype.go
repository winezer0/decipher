package cracker

import "strings"

type ModeType string

const (
	ModeAdded   ModeType = "added"
	ModeEncrypt ModeType = "encrypt"
	ModeDecrypt ModeType = "decrypt"
)

// ResolveMode 使用前缀匹配解析模式
// 逻辑：
// 1. 转为小写并去除空格
// 2. 如果以 "add" 开头 -> ModeAdded
// 3. 如果以 "enc" 开头 -> ModeEncrypt
// 4. 如果以 "dec" 开头 -> ModeDecrypt
func ResolveMode(input string) ModeType {
	key := strings.ToLower(strings.TrimSpace(input))

	if key == "" {
		return ModeDecrypt
	}
	// 注意匹配顺序：如果有重叠的前缀，长的应该放在前面检查。
	// 这里 add/enc/dec 没有重叠，顺序不重要。
	if strings.HasPrefix(key, "add") {
		return ModeAdded
	}
	if strings.HasPrefix(key, "enc") {
		return ModeEncrypt
	}
	if strings.HasPrefix(key, "dec") {
		return ModeDecrypt
	}
	return ModeDecrypt
}
