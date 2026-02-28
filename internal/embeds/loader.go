package embeds

import (
	"os"
)

// LoadFromFile 加载字典文件
func LoadFromFile(path string) (*os.File, error) {
	return os.Open(path)
}
