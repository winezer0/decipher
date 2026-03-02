package myutils

import (
	"os"
	"strings"

	"github.com/winezer0/xutils/logging"
	"github.com/winezer0/xutils/utils"
)

// ConvertStringsToFiles 检查 inputs 中的元素是否为已存在的文件路径。
//  1. 如果所有元素都是已存在的文件，直接返回原切片。
//  2. 如果包含非文件路径的字符串，则将所有内容合并写入到指定的 filePath 中，
//     并返回仅包含该新文件路径的切片。
//
// 参数:
//
//	inputs: 输入列表，可能是文件路径，也可能是纯文本字符串。
//	filePath: 当需要生成文件时，目标文件的完整路径。
func ConvertStringsToFiles(inputs []string, filePath string) []string {
	if len(inputs) == 0 {
		return inputs
	}

	// 第一步：检查是否所有输入都是已存在的文件
	allAreFiles := true
	for _, input := range inputs {
		// 忽略空字符串，视为需要处理的文本
		if strings.TrimSpace(input) == "" {
			allAreFiles = false
			break
		}

		info, err := os.Stat(input)
		if err != nil || info.IsDir() {
			// 路径不存在或者是目录，说明不是有效的文件路径
			allAreFiles = false
			break
		}
	}

	// 情况 A: 全都是已存在的文件，直接返回，不做任何操作
	if allAreFiles {
		return inputs
	}

	// 情况 B: 包含字符串或非存在路径，需要生成临时文件
	// 构建文件内容：将 inputs 中的所有元素用换行符连接
	// 这样无论是原来的文件路径字符串，还是纯文本，都被当作内容写入
	content := strings.Join(inputs, "\n")

	// 写入文件
	// 注意：这里选择每次覆盖写入。如果希望追加，可使用 OpenFile + os.O_APPEND
	if err := utils.SaveToFile(filePath, []byte(content)); err != nil {
		logging.Warnf("Failed to write temp file %s: %v", filePath, err)
		// 写入失败，返回原列表，避免下游拿到无效的文件路径
		return inputs
	}

	logging.Debugf("Merged %d inputs (strings/files) into temp file: %s", len(inputs), filePath)

	// 返回仅包含新生成文件路径的切片
	return []string{filePath}
}
