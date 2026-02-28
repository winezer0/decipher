package embeds

import (
	"bytes"
	_ "embed"
	"io"
)

//go:embed dicts.txt
var dictContent []byte

// GetBuiltinDict 返回内置字典的 Reader
func GetBuiltinDict() io.ReadSeeker {
	return bytes.NewReader(dictContent)
}
