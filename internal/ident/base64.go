package ident

import (
	"github.com/winezer0/decipher/internal/algo/types"
	"encoding/base64"
)

// IsValidBase64Str 检查输入的token字符串是否仅包含标准Base64允许的字符
// 标准Base64字符集：A-Z、a-z、0-9、+、/、=
// 参数: token - 需要校验的字符串
// 返回值: bool - true表示字符全部合法，false表示包含非法字符
func IsValidBase64StrWithDecode(token string) (decode string, isBase64 bool) {
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", false
	}
	if !types.IsPrintableUTF8(decoded) {
		return "", false
	}
	return string(decoded), true
}

func IsValidBase64Str(token string) bool {
	_, isBase64 := IsValidBase64StrWithDecode(token)
	return isBase64
}

// IsValidURLBase64Str 检查输入字符串是否仅包含URL安全的Base64字符
// URL Base64字符集：A-Z、a-z、0-9、-（替换+）、_（替换/）、=（可选补位符）
// 参数: token - 需要校验的URL Base64字符串
// 返回值: bool - true表示字符全部合法，false表示包含非法字符
func IsValidURLBase64Str(token string) bool {
	// 可选：如果业务要求空字符串非法，可添加这行
	// if len(token) == 0 {
	//     return false
	// }

	// 遍历每个字符做校验
	for i := 0; i < len(token); i++ {
		c := token[i]
		// 核心：替换 + → -、/ → _，其余字符集不变
		isValid := (c >= 'A' && c <= 'Z') || // 大写字母
			(c >= 'a' && c <= 'z') || // 小写字母
			(c >= '0' && c <= '9') || // 数字
			c == '-' || c == '_' || c == '=' // URL安全特殊符 + 可选补位符
		if !isValid {
			return false
		}
	}
	return true
}
