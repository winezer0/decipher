package algo

import "encoding/hex"

// DecodeHexSafe 安全地解码 hex 字符串，处理奇数长度的情况
func DecodeHexSafe(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		s = "0" + s
	}
	return hex.DecodeString(s)
}
