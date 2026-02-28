package sha

import (
	"crypto/sha512"
	"encoding/hex"
	"io"
)

func sha512Hex(s string) string {
	h := sha512.New()
	io.WriteString(h, s)
	return hex.EncodeToString(h.Sum(nil))
}
