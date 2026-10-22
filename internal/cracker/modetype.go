package cracker

import "strings"

type ModeType string

const (
	ModeAdded   ModeType = "added"
	ModeEncrypt ModeType = "encrypt"
	ModeDecrypt ModeType = "decrypt"
	ModeIdent   ModeType = "ident"
)

// ResolveMode 仅接受明确的模式名称及其完整别名；未知值返回空模式。
func ResolveMode(input string) ModeType {
	switch strings.ToLower(strings.TrimSpace(input)) {
	case "add", "added":
		return ModeAdded
	case "enc", "encrypt":
		return ModeEncrypt
	case "dec", "decrypt":
		return ModeDecrypt
	case "id", "ident", "identify":
		return ModeIdent
	default:
		return ""
	}
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
