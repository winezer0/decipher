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
