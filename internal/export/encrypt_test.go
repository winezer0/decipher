package export

import (
	"github.com/winezer0/decipher/internal/cracker"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestExportEncryptRoundTrip(t *testing.T) {
	results := []cracker.EncryptResult{{Algorithm: "algo:名", Hash: "hash:,\"", Salt: "盐:,\"\nnext", Plaintext: "文本:,\"\nnext"}}
	for _, format := range []string{"csv", "json"} {
		t.Run(format, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "result."+format)
			for _, input := range [][]cracker.EncryptResult{results, nil} {
				if err := ExportEncrypt(path, input, format); err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if format == "json" {
					var decoded []cracker.EncryptResult
					if err := json.Unmarshal(data, &decoded); err != nil {
						t.Fatal(err)
					}
					if input == nil {
						if strings.TrimSpace(string(data)) != "[]" {
							t.Fatalf("expected empty array: %s", data)
						}
					} else if !reflect.DeepEqual(decoded, input) {
						t.Fatalf("fields changed: %#v", decoded)
					}
				} else {
					rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
					if err != nil {
						t.Fatal(err)
					}
					want := [][]string{{"algorithm", "hash", "salt", "plaintext"}}
					for _, r := range input {
						want = append(want, []string{r.Algorithm, r.Hash, r.Salt, r.Plaintext})
					}
					if !reflect.DeepEqual(rows, want) {
						t.Fatalf("fields changed: %#v", rows)
					}
				}
			}
		})
	}
}
