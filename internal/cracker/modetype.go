package cracker

import "strings"

type ModeType string

const (
	ModeAdded   ModeType = "added"
	ModeEncrypt ModeType = "encrypt"
	ModeDecrypt ModeType = "decrypt"
	ModeIdent   ModeType = "ident"
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
	if strings.HasPrefix(key, "id") {
		return ModeIdent
	}
	return ModeDecrypt
}

// ParseModeTypes 接收字符串模式列表，返回解析后的ModeType列表
func ParseModeTypes(modeStrings []string) []ModeType {
	var modeTypes []ModeType
	for _, m := range modeStrings {
		modeTypes = append(modeTypes, ResolveMode(m))
	}
	return modeTypes
}

// HasMode 接收模式列表和目标模式，返回是否包含该模式
func HasMode(modeTypes []ModeType, target ModeType) bool {
	for _, m := range modeTypes {
		if m == target {
			return true
		}
	}
	return false
}
