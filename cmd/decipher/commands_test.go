package main

import (
	"crypto/md5"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestCLICommandHelpAndQueries(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {"enc", "--help"}, {"dec", "--help"}, {"id", "--help"}, {"dict-add", "--help"}, {"predb-init", "--help"}, {"--list"}, {"--version"}} {
		dir := t.TempDir()
		out, code := runCLI(t, dir, args...)
		if code != 0 || !utf8.ValidString(out) {
			t.Fatalf("%v exit %d: %s", args, code, out)
		}
		if strings.IndexFunc(out, func(r rune) bool { return unicode.Is(unicode.Han, r) }) >= 0 {
			t.Fatalf("%v produced non-English CLI output: %s", args, out)
		}
		requireMissing(t, filepath.Join(dir, "decipher_db"))
		requireMissing(t, filepath.Join(dir, "decipher_cache"))
	}
}

func TestCLIDictionaryOperationsAreSeparate(t *testing.T) {
	dir := t.TempDir()
	plain := writeFixture(t, dir, "decipher_db/builtin-plain.txt", "original\n")
	salt := writeFixture(t, dir, "decipher_db/builtin-salt.txt", "salt-original\n")
	input := writeFixture(t, dir, "words.txt", "123456\n")
	out, code := runCLI(t, dir, "dict-add", "-p", "file:"+input, "-s", "str:salt-added", "-R")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	for path, want := range map[string]string{plain: "original\n123456\n", salt: "salt-original\nsalt-added\n"} {
		data, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(data), want) {
			t.Fatalf("dictionary %q: %q, %v", path, data, err)
		}
	}
	files, _ := filepath.Glob(filepath.Join(dir, "decipher_db", "*.predb"))
	if len(files) != 0 {
		t.Fatalf("dict-add generated predb: %v", files)
	}
	beforePlain, _ := os.ReadFile(plain)
	beforeSalt, _ := os.ReadFile(salt)
	cache := writeFixture(t, dir, "decipher_db/cache_md5($pass).predb", "existing-marker\n")
	for _, args := range [][]string{
		{"predb-init", "-p", "file:" + input},
		{"predb-init"}, // Falls back to the dictionaries populated by dict-add.
	} {
		out, code := runCLI(t, dir, append(args, "-a", "md5($pass)", "-A", "-R")...)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
	}
	for path, want := range map[string]string{plain: string(beforePlain), salt: string(beforeSalt), input: "123456\n"} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != want {
			t.Fatalf("predb-init modified %q: %q, %v", path, data, err)
		}
	}
	data, err := os.ReadFile(cache)
	if err != nil || !strings.HasPrefix(string(data), "existing-marker\n") || !strings.Contains(string(data), testHash) {
		t.Fatalf("predb was not appended: %q, %v", data, err)
	}
	// Algorithms not eligible for pre-computation must fail rather than fall back.
	out, code = runCLI(t, dir, "predb-init", "-a", "md5($salt.$pass)", "-A", "-R")
	if code != 1 || !strings.Contains(out, "no algorithms selected for pre-computation") {
		t.Fatalf("exit %d: %s", code, out)
	}
	out, code = runCLI(t, dir, "dict-add")
	if code != 1 || !strings.Contains(out, "requires -p or -s") {
		t.Fatalf("exit %d: %s", code, out)
	}
}

func TestCLICommandAffixesAndCustomPaths(t *testing.T) {
	dir := t.TempDir()
	out, code := runCLI(t, dir, "--predb-dir", "custom db", "enc", "-p", "str:123456", "-s", "str:salt", "--sp", "prefix", "--ps", "suffix", "-a", "md5($salt.$pass)", "-A", "--run-cache-dir", "custom cache", "-O", "json", "-w", "1", "-R")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	data, err := os.ReadFile(filepath.Join(dir, "decipher.enc.json"))
	hash := fmt.Sprintf("%x", md5.Sum([]byte("prefixsalt123456suffix")))
	if err != nil || !strings.Contains(string(data), hash) {
		t.Fatalf("command options lost: %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "custom db", "builtin-plain.txt")); err != nil {
		t.Fatal(err)
	}
	requireMissing(t, filepath.Join(dir, "decipher_db"))
}

func TestCLISuccessCacheAppendAndFailureOverwrite(t *testing.T) {
	dir := t.TempDir()
	for _, plain := range []string{"123456", "password"} {
		hash := fmt.Sprintf("%x", md5.Sum([]byte(plain)))
		out, code := runCLI(t, dir, "dec", "-i", "str:"+hash, "-p", "str:"+plain, "-a", "md5($pass)", "-A", "--npc", "-R")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "decipher_db", "success.cache"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
	if err != nil || len(rows) != 3 {
		t.Fatalf("cache not appended: %q, %v", rows, err)
	}
	failure := writeFixture(t, dir, "decipher.failure.csv", "old-failure-marker\n")
	hash := fmt.Sprintf("%x", md5.Sum([]byte("unmatched")))
	out, code := runCLI(t, dir, "dec", "-i", "str:"+hash, "-p", "str:wrong", "-a", "md5($pass)", "-A", "--npc", "-R")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	data, err = os.ReadFile(failure)
	if err != nil || strings.Contains(string(data), "old-failure-marker") || !strings.Contains(string(data), hash) {
		t.Fatalf("failure records not replaced: %q, %v", data, err)
	}
	before := string(data)
	out, code = runCLI(t, dir, "dec", "-i", "str:"+testHash, "-a", "md5($pass)", "-A", "--npc", "-R")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	data, err = os.ReadFile(failure)
	if err != nil || string(data) != before {
		t.Fatalf("no-failure run changed failure file: %q, %v", data, err)
	}
}
