package main

import (
	"crypto/md5"
	"github.com/winezer0/decipher/internal/cracker"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestCLIEncryptDictionaryCleaningAndDuplicates(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "plains.txt", " 123456 \r\n123456\n\x00123456\x00\n\ufeff123456\n#literal")
	out, code := runCLI(t, dir, "enc", "-p", "file:plains.txt", "-a", "md5($pass)", "-A", "-O", "json", "--workers", "2")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	data, err := os.ReadFile(filepath.Join(dir, "decipher.enc.json"))
	if err != nil {
		t.Fatal(err)
	}
	var results []cracker.EncryptResult
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, result := range results {
		if result.Hash != fmt.Sprintf("%x", md5.Sum([]byte(result.Plaintext))) || result.Salt != "" || result.Algorithm != "md5($pass)" {
			t.Fatalf("invalid result: %+v", result)
		}
		got = append(got, result.Plaintext)
	}
	want := []string{"123456", "123456", "123456", "\ufeff123456", "#literal"}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestCLIIdentDictionaryCommentsAndDuplicates(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "hashes.txt", " # ignored\r\n\n "+testHash+":salt:ignored\r\n\x00"+testHash+":other\x00\n")
	out, code := runCLI(t, dir, "id", "-i", "file:hashes.txt", "-O", "json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	data, err := os.ReadFile(filepath.Join(dir, "decipher.id.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("duplicate targets changed: %s", data)
	}
	for _, row := range rows {
		if row["hash"] != testHash {
			t.Fatalf("invalid target: %s", data)
		}
	}
}
