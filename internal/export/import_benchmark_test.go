package export

import (
	"github.com/winezer0/decipher/internal/cracker"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type successCacheWorkload struct {
	records, targets, hits, unique int
}

var successCacheWorkloads = []successCacheWorkload{
	{1000, 1, 1, 1000},
	{100000, 1, 1, 100000},
	{100000, 1000, 1000, 100000},
	{100000, 100000, 100000, 100000},
	{100000, 1000, 0, 100000},
	{100000, 1000, 100, 100000},
	{100000, 1000, 1000, 1000},
}

func (s successCacheWorkload) name() string {
	return fmt.Sprintf("records=%d/targets=%d/hits=%d/unique=%d", s.records, s.targets, s.hits, s.unique)
}

func successCacheFixture(tb testing.TB, size successCacheWorkload) (string, []cracker.HashSaltTarget) {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "success.cache")
	file, err := os.Create(path)
	if err != nil {
		tb.Fatal(err)
	}
	writer := csv.NewWriter(file)
	if err := writer.Write([]string{"hash_salt", "clear_text", "salt", "algo", "algo_type"}); err != nil {
		tb.Fatal(err)
	}
	for i := 0; i < size.records; i++ {
		hash := fmt.Sprintf("%032x", i%size.unique)
		if err := writer.Write([]string{hash, "password", "", "md5($pass)", "static"}); err != nil {
			tb.Fatal(err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		tb.Fatal(err)
	}
	if err := file.Close(); err != nil {
		tb.Fatal(err)
	}
	targets := make([]cracker.HashSaltTarget, size.targets)
	for i := range targets {
		value := size.unique + i
		if i < size.hits {
			value = size.unique - size.hits + i
		}
		targets[i] = cracker.HashSaltTarget{Hash: fmt.Sprintf("%032x", value)}
	}
	return path, targets
}

func BenchmarkLoadSuccessCacheMap(b *testing.B) {
	for _, size := range successCacheWorkloads {
		b.Run(size.name(), func(b *testing.B) {
			path, targets := successCacheFixture(b, size)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				results := LoadSuccessCacheMap(path, targets)
				if len(results) != size.hits {
					b.Fatalf("got %d results, want %d", len(results), size.hits)
				}
				for j, target := range targets {
					result, ok := results[target.Hash]
					if ok != (j < size.hits) || (ok && result.Plaintext != "password") {
						b.Fatalf("incorrect result for %s", target.Hash)
					}
				}
			}
		})
	}
}
