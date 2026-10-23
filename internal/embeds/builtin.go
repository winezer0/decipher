package embeds

import (
	"bytes"
	_ "embed"
	utils "github.com/winezer0/xutils/pathutils"
	"io"
	"os"
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

func WriteEmbedToFile(filename string, reader io.ReadSeeker) error {
	utils.EnsureDir(filename, true)
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, reader)
	return err
}
