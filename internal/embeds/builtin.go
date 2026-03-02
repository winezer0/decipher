package embeds

import (
	"bytes"
	_ "embed"
	"io"
)

//go:embed dict_plains.txt
var plainContent []byte

// GetBuiltinPlainsDict 返回内置 明文 字典的 Reader
func GetBuiltinPlainsDict() io.ReadSeeker {
	return bytes.NewReader(plainContent)
}

//go:embed dict_salts.txt
var saltContent []byte

// GetBuiltinSaltsDict 返回内置 salt 字典的 Reader
func GetBuiltinSaltsDict() io.ReadSeeker {
	return bytes.NewReader(saltContent)
}
