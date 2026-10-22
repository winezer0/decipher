package export

import (
	"decipher/internal/algo"
	"decipher/internal/algo/md5"
	"decipher/internal/cracker"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func encryptFixture(t testing.TB, large bool) (*cracker.Engine, []string, []string, []algo.Algorithm, int) {
	t.Helper()
	dir := t.TempDir()
	count, salts := 10, 9
	if large {
		count, salts = 100, 999
	}
	var plains, secrets strings.Builder
	for i := 0; i < count; i++ {
		fmt.Fprintf(&plains, "password-%06d\n", i)
	}
	for i := 0; i < salts; i++ {
		fmt.Fprintf(&secrets, "salt-%06d\n", i)
	}
	plainPath, saltPath := filepath.Join(dir, "plains"), filepath.Join(dir, "salts")
	if err := os.WriteFile(plainPath, []byte(plains.String()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(saltPath, []byte(secrets.String()), 0600); err != nil {
		t.Fatal(err)
	}
	return cracker.NewEngine(4, dir, ""), []string{plainPath}, []string{saltPath}, []algo.Algorithm{&md5.MD5SaltPassAlgo{}}, count * (salts + 1)
}

func benchmarkEncryptOutput(engine *cracker.Engine, plains, salts []string, algos []algo.Algorithm, path, format string) error {
	return ExportEncryptStream(path, format, func(emit func(cracker.EncryptResult) error) error {
		return engine.RunEncryptStream(plains, salts, algos, emit)
	})
}

func BenchmarkEncryptOutput(b *testing.B) {
	for _, large := range []bool{false, true} {
		for _, format := range []string{"csv", "json"} {
			b.Run(fmt.Sprintf("large=%t/%s", large, format), func(b *testing.B) {
				engine, plains, salts, algos, count := encryptFixture(b, large)
				path := filepath.Join(b.TempDir(), "result")
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if err := benchmarkEncryptOutput(engine, plains, salts, algos, path, format); err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()
				verifyEncryptOutput(b, path, format, count)
			})
		}
	}
}

func verifyEncryptOutput(t testing.TB, path, format string, want int) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	count := 0
	if format == "json" {
		decoder := json.NewDecoder(file)
		if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
			t.Fatalf("invalid array: %v %v", token, err)
		}
		for decoder.More() {
			var result cracker.EncryptResult
			if err := decoder.Decode(&result); err != nil {
				t.Fatal(err)
			}
			count++
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
			t.Fatalf("invalid array end: %v %v", token, err)
		}
		if _, err := decoder.Token(); err != io.EOF {
			t.Fatalf("trailing JSON: %v", err)
		}
	} else {
		reader := csv.NewReader(file)
		if _, err := reader.Read(); err != nil {
			t.Fatal(err)
		}
		for {
			_, err := reader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			count++
		}
	}
	if count != want {
		t.Fatalf("got %d results, want %d", count, want)
	}
}
