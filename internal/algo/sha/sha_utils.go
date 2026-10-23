package sha

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"io"
)

func sha512Hex(s string) string {
	h := sha512.New()
	io.WriteString(h, s)
	return hex.EncodeToString(h.Sum(nil))
}

func sha1Hex(s string) string {
	h := sha1.New()
	io.WriteString(h, s)
	return hex.EncodeToString(h.Sum(nil))
}

func sha256Hex(s string) string {
	h := sha256.New()
	io.WriteString(h, s)
	return hex.EncodeToString(h.Sum(nil))
}

// 直接比较摘要，避免每次验证生成十六进制字符串及小写副本。
func sha1Matches(token string, sum [sha1.Size]byte) bool {
	if len(token) != hex.EncodedLen(sha1.Size) {
		return false
	}
	var expected [sha1.Size]byte
	if _, err := hex.Decode(expected[:], []byte(token)); err != nil {
		return false
	}
	return expected == sum
}

func sha256Matches(token string, sum [sha256.Size]byte) bool {
	if len(token) != hex.EncodedLen(sha256.Size) {
		return false
	}
	var expected [sha256.Size]byte
	if _, err := hex.Decode(expected[:], []byte(token)); err != nil {
		return false
	}
	return expected == sum
}
