package export

import (
	"decipher/internal/cracker"
	"encoding/csv"
	"fmt"
	"os"
)

// ExportCSV 将解密结果追加导出到 CSV 文件。
// 如果文件不存在或为空，会自动写入表头；否则直接追加数据。
func ExportCSV(filePath string, crackerResults []cracker.CrackerResult) error {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("获取文件信息失败: %w", err)
	}

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if info.Size() == 0 {
		header := []string{"hash_salt", "clear_text", "salt", "algo", "algo_type"}
		if err := writer.Write(header); err != nil {
			return fmt.Errorf("写入表头失败: %w", err)
		}
	}

	for _, res := range crackerResults {
		hashSalt := res.Hash
		if res.Salt != "" {
			hashSalt = fmt.Sprintf("%s:%s", res.Hash, res.Salt)
		}

		record := []string{
			hashSalt,
			res.Plaintext,
			res.Salt,
			res.Algorithm,
			res.AlgoType,
		}

		if err := writer.Write(record); err != nil {
			return fmt.Errorf("写入记录失败: %w", err)
		}
	}

	writer.Flush()
	return writer.Error()
}

// ExportFailureCSV 将解密失败的目标导出到 CSV 文件
func ExportFailureCSV(filePath string, failedTargets map[string]cracker.Target) error {
	if len(failedTargets) == 0 {
		return nil
	}

	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("获取文件信息失败: %w", err)
	}

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if info.Size() == 0 {
		header := []string{"hash", "salt"}
		if err := writer.Write(header); err != nil {
			return fmt.Errorf("写入表头失败: %w", err)
		}
	}

	for _, t := range failedTargets {
		record := []string{
			t.Hash,
			t.Salt,
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("写入记录失败: %w", err)
		}
	}

	writer.Flush()
	return writer.Error()
}
