package export

import (
	"bytes"
	"github.com/winezer0/decipher/internal/cracker"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type encryptFaultWriter struct {
	bytes.Buffer
	writeErr, closeErr error
	closed             bool
}

func (w *encryptFaultWriter) Write(p []byte) (int, error) {
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	return w.Buffer.Write(p)
}
func (w *encryptFaultWriter) Close() error { w.closed = true; return w.closeErr }

func TestEncryptStreamOrderAndIncrementalWrites(t *testing.T) {
	for _, format := range []string{"csv", "json"} {
		t.Run(format, func(t *testing.T) {
			var output bytes.Buffer
			var want []cracker.EncryptResult
			err := writeEncryptStream(&output, format, func(emit func(cracker.EncryptResult) error) error {
				for i := 0; i < 3000; i++ {
					result := cracker.EncryptResult{Algorithm: fmt.Sprintf("algo-%d", i%3), Hash: fmt.Sprint(i), Salt: "盐,\"\n:", Plaintext: strings.Repeat("中文,\"\n", 10)}
					want = append(want, result)
					if err := emit(result); err != nil {
						return err
					}
				}
				if output.Len() == 0 {
					t.Fatal("all output buffered until source finished")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			var got []cracker.EncryptResult
			if format == "json" {
				if err := json.Unmarshal(output.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
			} else {
				rows, err := csv.NewReader(&output).ReadAll()
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range rows[1:] {
					got = append(got, cracker.EncryptResult{Algorithm: row[0], Hash: row[1], Salt: row[2], Plaintext: row[3]})
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatal("result fields or arrival order changed")
			}
		})
	}
}

func TestEncryptStreamErrors(t *testing.T) {
	failure := errors.New("injected failure")
	for _, format := range []string{"csv", "json"} {
		for _, stage := range []string{"write", "flush", "close", "source"} {
			t.Run(format+"/"+stage, func(t *testing.T) {
				writer := &encryptFaultWriter{}
				if stage == "write" || stage == "flush" {
					writer.writeErr = failure
				}
				if stage == "close" || stage == "source" {
					writer.closeErr = errors.New("close failure")
				}
				if stage == "close" {
					writer.closeErr = failure
				}
				count := 0
				err := exportEncryptStream("unused", format, func(emit func(cracker.EncryptResult) error) error {
					if stage == "source" {
						return failure
					}
					limit := 1
					if stage == "write" {
						limit = 10000
					}
					for count < limit {
						count++
						if err := emit(cracker.EncryptResult{Plaintext: strings.Repeat("x", 1000)}); err != nil {
							return err
						}
					}
					return nil
				}, func(string) (io.WriteCloser, error) { return writer, nil })
				if !errors.Is(err, failure) || !writer.closed {
					t.Fatalf("error=%v closed=%t", err, writer.closed)
				}
				if stage == "write" && count >= 10000 {
					t.Fatal("did not stop source on write failure")
				}
			})
		}
	}
}

func TestEncryptStreamRejectsBeforeSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keep")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	source := func(func(cracker.EncryptResult) error) error { t.Fatal("source must not run"); return nil }
	if err := ExportEncryptStream(path, "yaml", source); err == nil {
		t.Fatal("expected format error")
	}
	if data, _ := os.ReadFile(path); string(data) != "keep" {
		t.Fatal("invalid format truncated file")
	}
	if err := ExportEncryptStream(dir, "csv", source); err == nil {
		t.Fatal("expected open error")
	}
}
