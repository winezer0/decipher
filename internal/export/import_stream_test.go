package export

import (
	"github.com/winezer0/decipher/internal/cracker"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func successCacheCSV(t *testing.T, rows ...[]string) string {
	t.Helper()
	var data strings.Builder
	writer := csv.NewWriter(&data)
	if err := writer.WriteAll(rows); err != nil {
		t.Fatal(err)
	}
	return data.String()
}

func TestLoadSuccessCacheMapManyDistinctResults(t *testing.T) {
	rows := [][]string{{"hash_salt", "clear_text", "salt", "algo", "algo_type"}}
	var targets []cracker.HashSaltTarget
	for i := 0; i < 150; i++ {
		hash := fmt.Sprintf("hash-%d", i)
		targets = append(targets, cracker.HashSaltTarget{Hash: hash})
		rows = append(rows, []string{hash, fmt.Sprintf("plain-%d", i), fmt.Sprintf("salt-%d", i), "md5", "static"})
	}
	targets = append(targets, cracker.HashSaltTarget{Hash: "missing"})
	rows = append(rows, []string{"hash-0", "latest", "latest-salt", "md5", "static"})
	path := filepath.Join(t.TempDir(), "success.cache")
	if err := os.WriteFile(path, []byte(successCacheCSV(t, rows...)), 0600); err != nil {
		t.Fatal(err)
	}
	results := LoadSuccessCacheMap(path, targets)
	if len(results) != 150 {
		t.Fatalf("incorrect result count: %d", len(results))
	}
	seen := make(map[*cracker.CrackerResult]bool)
	for i := 0; i < 150; i++ {
		hash := fmt.Sprintf("hash-%d", i)
		got := results[hash]
		plain, salt := fmt.Sprintf("plain-%d", i), fmt.Sprintf("salt-%d", i)
		if i == 0 {
			plain, salt = "latest", "latest-salt"
		}
		if got == nil || got.Hash != hash || got.Plaintext != plain || got.Salt != salt || seen[got] {
			t.Fatalf("result overwritten or aliased: %s: %#v", hash, got)
		}
		seen[got] = true
	}
}

func TestLoadSuccessCacheMapStreaming(t *testing.T) {
	header := []string{"hash_salt", "clear_text", "salt", "algo", "algo_type"}
	row := func(hash, plain, salt string) []string {
		return []string{hash, plain, salt, "md5($pass)", "static"}
	}
	result := func(hash, plain, salt string) *cracker.CrackerResult {
		return &cracker.CrackerResult{Hash: hash, Plaintext: plain, Salt: salt, Algorithm: "md5($pass)", AlgoType: "static"}
	}
	valid := successCacheCSV(t, header, row("wanted", "password", ""))
	for _, tc := range []struct {
		name, data, separator string
		targets               []cracker.HashSaltTarget
		want                  map[string]*cracker.CrackerResult
	}{
		{name: "selected only", data: successCacheCSV(t, header, row("wanted", "password", ""), row("unrelated", "discard", "")),
			targets: []cracker.HashSaltTarget{{Hash: "wanted"}}, want: map[string]*cracker.CrackerResult{"wanted": result("wanted", "password", "")}},
		{name: "no match", data: valid, targets: []cracker.HashSaltTarget{{Hash: "missing"}}},
		{name: "remove unmatched placeholders", data: valid,
			targets: []cracker.HashSaltTarget{{Hash: "wanted"}, {Hash: "missing"}, {Hash: "MISSING"}},
			want:    map[string]*cracker.CrackerResult{"wanted": result("wanted", "password", "")}},
		{name: "nil targets", data: valid},
		{name: "empty targets", data: valid, targets: []cracker.HashSaltTarget{}},
		{name: "header only", data: successCacheCSV(t, header), targets: []cracker.HashSaltTarget{{Hash: "wanted"}}},
		{name: "no header", data: successCacheCSV(t, row("wanted", "password", "")),
			targets: []cracker.HashSaltTarget{{Hash: "wanted"}}, want: map[string]*cracker.CrackerResult{"wanted": result("wanted", "password", "")}},
		{name: "case whitespace and duplicate last wins", data: successCacheCSV(t, header, row("wanted", "old", ""), row(" WANTED ", "new", "salt")),
			targets: []cracker.HashSaltTarget{{Hash: "WaNtEd"}, {Hash: "wanted"}}, want: map[string]*cracker.CrackerResult{"wanted": result("WANTED", "new", "salt")}},
		{name: "quoted multiline and separator", data: successCacheCSV(t, header, row("wanted:fallback:rest", "中文,quoted\"\nnext:line", "")),
			targets: []cracker.HashSaltTarget{{Hash: "wanted"}}, want: map[string]*cracker.CrackerResult{"wanted": result("wanted", "中文,quoted\"\nnext:line", "fallback:rest")}},
		{name: "explicit salt wins", data: successCacheCSV(t, header, row("wanted:fallback", "password", "explicit")),
			targets: []cracker.HashSaltTarget{{Hash: "wanted"}}, want: map[string]*cracker.CrackerResult{"wanted": result("wanted", "password", "explicit")}},
		{name: "custom separator", separator: "||", data: successCacheCSV(t, header, row("wanted||salt||tail", "password", "")),
			targets: []cracker.HashSaltTarget{{Hash: "wanted"}}, want: map[string]*cracker.CrackerResult{"wanted": result("wanted", "password", "salt||tail")}},
		{name: "preserve earlier matching fields", data: successCacheCSV(t, header, row("first", "first-password", "first-salt"), row("second", "second-password", "second-salt")),
			targets: []cracker.HashSaltTarget{{Hash: "first"}, {Hash: "second"}}, want: map[string]*cracker.CrackerResult{"first": result("first", "first-password", "first-salt"), "second": result("second", "second-password", "second-salt")}},
		{name: "malformed after match discards prefix", data: valid + "unrelated,\"unterminated", targets: []cracker.HashSaltTarget{{Hash: "wanted"}}},
		{name: "field count error discards prefix", data: valid + "unrelated,short\n", targets: []cracker.HashSaltTarget{{Hash: "wanted"}}},
		{name: "malformed first row", data: "\"unterminated", targets: []cracker.HashSaltTarget{{Hash: "wanted"}}},
		{name: "short rows ignored", data: "wanted,password\n", targets: []cracker.HashSaltTarget{{Hash: "wanted"}}},
		{name: "empty hash ignored", data: successCacheCSV(t, header, row("", "password", "")), targets: []cracker.HashSaltTarget{{Hash: ""}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := cracker.ConcatSymbol
			t.Cleanup(func() { cracker.ConcatSymbol = original })
			cracker.ConcatSymbol = ":"
			if tc.separator != "" {
				cracker.ConcatSymbol = tc.separator
			}
			path := filepath.Join(t.TempDir(), "success.cache")
			if err := os.WriteFile(path, []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			got := LoadSuccessCacheMap(path, tc.targets)
			if tc.want == nil {
				tc.want = make(map[string]*cracker.CrackerResult)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
			for hash, result := range got {
				if result == nil {
					t.Fatalf("unmatched placeholder returned for %s", hash)
				}
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != tc.data {
				t.Fatalf("cache changed during load: %v", err)
			}
		})
	}
}
