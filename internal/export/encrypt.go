package export

import (
	"bufio"
	"bytes"
	"decipher/internal/cracker"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// EncryptSource 按计算完成顺序交付结果，消费失败时必须停止并返回该错误。
type EncryptSource func(emit func(cracker.EncryptResult) error) error

// ExportEncrypt writes structured encryption results, overwriting the target.
func ExportEncrypt(path string, results []cracker.EncryptResult, format string) error {
	return ExportEncryptStream(path, format, func(emit func(cracker.EncryptResult) error) error {
		for _, result := range results {
			if err := emit(result); err != nil {
				return err
			}
		}
		return nil
	})
}

// ExportEncryptStream 逐条序列化，覆盖目标文件；失败时文件可能包含部分结果。
func ExportEncryptStream(path, format string, source EncryptSource) error {
	return exportEncryptStream(path, format, source, func(path string) (io.WriteCloser, error) { return os.Create(path) })
}

func exportEncryptStream(path, format string, source EncryptSource, open func(string) (io.WriteCloser, error)) (err error) {
	if format != "csv" && format != "json" {
		return fmt.Errorf("invalid encryption output format: %s", format)
	}
	file, err := open(path)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
	}()
	return writeEncryptStream(file, format, source)
}

func writeEncryptStream(output io.Writer, format string, source EncryptSource) error {
	buffer := bufio.NewWriterSize(output, 64*1024)
	var emit func(cracker.EncryptResult) error
	var finish func() error
	if format == "json" {
		if _, err := buffer.WriteString("["); err != nil {
			return err
		}
		first := true
		var record bytes.Buffer
		var value cracker.EncryptResult
		encoder := json.NewEncoder(&record)
		emit = func(result cracker.EncryptResult) error {
			prefix := ",\n  "
			if first {
				prefix = "\n  "
				first = false
			}
			if _, err := buffer.WriteString(prefix); err != nil {
				return err
			}
			record.Reset()
			value = result
			if err := encoder.Encode(&value); err != nil {
				return err
			}
			encoded := record.Bytes()
			_, err := buffer.Write(encoded[:len(encoded)-1]) // Encoder 添加的换行由数组分隔符统一写入。
			return err
		}
		finish = func() error {
			suffix := "]\n"
			if !first {
				suffix = "\n]\n"
			}
			_, err := buffer.WriteString(suffix)
			return err
		}
	} else {
		writer := csv.NewWriter(buffer)
		if err := writer.Write([]string{"algorithm", "hash", "salt", "plaintext"}); err != nil {
			return err
		}
		emit = func(result cracker.EncryptResult) error {
			return writer.Write([]string{result.Algorithm, result.Hash, result.Salt, result.Plaintext})
		}
		finish = func() error { writer.Flush(); return writer.Error() }
	}
	if err := source(emit); err != nil {
		return err
	}
	if err := finish(); err != nil {
		return err
	}
	return buffer.Flush()
}
