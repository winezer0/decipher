package export

import (
	"decipher/internal/cracker"
	"encoding/csv"
	"fmt"
	"os"
	"strings"

	utils "github.com/winezer0/xutils/fileutils"
)

// ExportCSV 将解密结果追加导出到 CSV 文件。
// 如果文件不存在或为空，会自动写入表头；否则直接追加数据。
func ExportCSV(filePath string, crackerResults []cracker.CrackerResult, overwrite bool) error {
	flags := GetFileOpenMode(overwrite)
	file, err := os.OpenFile(filePath, flags, 0644)
	if err != nil {
		return fmt.Errorf("open file failed: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("get file information failed: %w", err)
	}

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if info.Size() == 0 {
		header := []string{"hash_salt", "clear_text", "salt", "algo", "algo_type"}
		if err := writer.Write(header); err != nil {
			return fmt.Errorf("write header failed: %w", err)
		}
	}

	for _, res := range crackerResults {
		hashSalt := res.Hash
		if res.Salt != "" {
			element := []string{res.Hash, res.Salt}
			hashSalt = strings.Join(element, cracker.ConcatSymbol)
		}

		record := []string{
			hashSalt,
			res.Plaintext,
			res.Salt,
			res.Algorithm,
			res.AlgoType,
		}

		if err := writer.Write(record); err != nil {
			return fmt.Errorf("write record failed: %w", err)
		}
	}

	writer.Flush()
	return writer.Error()
}

func GetFileOpenMode(overwrite bool) int {
	// 追加写模式：O_WRONLY(只写) + O_CREATE(不存在则创建) + O_APPEND(追加)
	flags := os.O_APPEND | os.O_CREATE | os.O_WRONLY
	if overwrite {
		// 覆盖写模式：O_WRONLY(只写) + O_CREATE(不存在则创建) + O_TRUNC(存在则截断清空)
		flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	return flags
}

// ExportJSON 将数据导出到 JSON 文件
func ExportJSON(filePath string, data interface{}) error {
	return utils.SaveJSON(filePath, data)
}

// ExportFailureCSV 将解密失败的目标导出到 CSV 文件
func ExportFailureCSV(filePath string, failedTargets map[string]cracker.HashSaltTarget, overwrite bool) error {
	if len(failedTargets) == 0 {
		return nil
	}

	flags := GetFileOpenMode(overwrite)
	file, err := os.OpenFile(filePath, flags, 0644)
	//file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open file failed: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("get file information failed: %w", err)
	}

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if info.Size() == 0 {
		header := []string{"hash", "salt"}
		if err := writer.Write(header); err != nil {
			return fmt.Errorf("write header failed: %w", err)
		}
	}

	for _, t := range failedTargets {
		record := []string{
			t.Hash,
			t.Salt,
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("write record failed: %w", err)
		}
	}

	writer.Flush()
	return writer.Error()
}

func ExportIdentCSV(filePath string, idResults []cracker.IdentResult, overwrite bool) error {
	flags := GetFileOpenMode(overwrite)
	file, err := os.OpenFile(filePath, flags, 0644)
	if err != nil {
		return fmt.Errorf("open file failed: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("get file information failed: %w", err)
	}

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if info.Size() == 0 {
		header := []string{"hash", "algos_names"}
		if err := writer.Write(header); err != nil {
			return fmt.Errorf("write header failed: %w", err)
		}
	}

	for _, r := range idResults {
		record := []string{
			r.Hash,
			strings.Join(r.AlgosNames, "/"),
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("write record failed: %w", err)
		}
	}

	writer.Flush()
	return writer.Error()
}
