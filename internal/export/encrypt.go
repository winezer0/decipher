package export

import (
	"decipher/internal/cracker"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
)

// ExportEncrypt writes structured encryption results, overwriting the target.
func ExportEncrypt(path string, results []cracker.EncryptResult, format string) (err error) {
	if format != "csv" && format != "json" {
		return fmt.Errorf("invalid encryption output format: %s", format)
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
	}()
	if format == "json" {
		if results == nil {
			results = []cracker.EncryptResult{}
		}
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		return encoder.Encode(results)
	}
	writer := csv.NewWriter(file)
	if err := writer.Write([]string{"algorithm", "hash", "salt", "plaintext"}); err != nil {
		return err
	}
	for _, result := range results {
		if err := writer.Write([]string{result.Algorithm, result.Hash, result.Salt, result.Plaintext}); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}
