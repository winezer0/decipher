package main

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/winezer0/decipher/internal/cracker"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func requireCLISuccess(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, code := runCLI(t, dir, args...)
	if code != 0 {
		t.Fatalf("%v exit %d: %s", args, code, out)
	}
	return out
}

func readJSONResults[T any](t *testing.T, dir, name string) []T {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	var results []T
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatalf("%s: %v, %s", name, err, data)
	}
	return results
}

func requireNoTemporaryDicts(t *testing.T, dir string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "decipher_cache", "decipher_*.txt"))
	if err != nil || len(files) != 0 {
		t.Fatalf("temporary dictionaries remain: %v, %v", files, err)
	}
}

func TestCLIRepeatedAndCommaSeparatedInputs(t *testing.T) {
	for name, input := range map[string][]string{
		"repeated": {"-p", "str:alpha", "-p", "str:beta", "-a", "md5($pass)", "-a", "sha1($pass)"},
		"comma":    {"-p", "str:alpha,str:beta", "-a", "md5($pass),sha1($pass)"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			args := append([]string{"enc"}, input...)
			requireCLISuccess(t, dir, append(args, "-A", "-O", "json", "-R")...)
			results := readJSONResults[cracker.EncryptResult](t, dir, "decipher.enc.json")
			want := make(map[string]string)
			for _, plain := range []string{"alpha", "beta"} {
				want["md5($pass)/"+plain] = fmt.Sprintf("%x", md5.Sum([]byte(plain)))
				want["sha1($pass)/"+plain] = fmt.Sprintf("%x", sha1.Sum([]byte(plain)))
			}
			if len(results) != len(want) {
				t.Fatalf("unexpected result count: %#v", results)
			}
			for _, result := range results {
				key := result.Algorithm + "/" + result.Plaintext
				if want[key] != result.Hash || result.Salt != "" {
					t.Fatalf("incorrect encryption result: %#v", result)
				}
				delete(want, key)
			}
			if len(want) != 0 {
				t.Fatalf("missing results: %v", want)
			}
			requireNoTemporaryDicts(t, dir)
		})
	}
}

func TestCLIAlgorithmMatchingModes(t *testing.T) {
	dir := t.TempDir()
	requireCLISuccess(t, dir, "enc", "-p", "str:123456", "-a", "md5", "-O", "json", "-R")
	results := readJSONResults[cracker.EncryptResult](t, dir, "decipher.enc.json")
	if len(results) < 2 {
		t.Fatalf("fuzzy match failed to select multiple algorithms: %#v", results)
	}
	for _, result := range results {
		if !strings.Contains(strings.ToLower(result.Algorithm), "md5") {
			t.Fatalf("unrelated algorithm: %#v", result)
		}
	}
	before, err := os.ReadFile(filepath.Join(dir, "decipher.enc.json"))
	if err != nil {
		t.Fatal(err)
	}
	out, code := runCLI(t, dir, "enc", "-p", "str:123456", "-a", "md5", "-A", "-O", "json", "-R")
	if code != 1 || !strings.Contains(out, "no algorithms") {
		t.Fatalf("exit %d: %s", code, out)
	}
	after, err := os.ReadFile(filepath.Join(dir, "decipher.enc.json"))
	if err != nil || string(before) != string(after) {
		t.Fatalf("failed selection modified previous results: %v", err)
	}
	requireNoTemporaryDicts(t, dir)
}

func TestCLIGeneratedPlaintexts(t *testing.T) {
	dir := t.TempDir()
	requireCLISuccess(t, dir, "enc", "-p", "gen:1:ab", "-a", "md5($pass)", "-A", "-O", "json", "-R")
	results := readJSONResults[cracker.EncryptResult](t, dir, "decipher.enc.json")
	got := make(map[string]string)
	for _, result := range results {
		got[result.Plaintext] = result.Hash
	}
	want := map[string]string{"a": fmt.Sprintf("%x", md5.Sum([]byte("a"))), "b": fmt.Sprintf("%x", md5.Sum([]byte("b")))}
	if len(results) != 2 || !reflect.DeepEqual(got, want) {
		t.Fatalf("incorrect generated results: %#v", results)
	}
	requireNoTemporaryDicts(t, dir)
}

func TestCLIDictionarySingleInputAndSelfAppend(t *testing.T) {
	for _, kind := range []string{"plain", "salt"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			plain := writeFixture(t, dir, "decipher_db/builtin-plain.txt", "plain-original\n")
			salt := writeFixture(t, dir, "decipher_db/builtin-salt.txt", "salt-original\n")
			flag := "-p"
			target, untouched := plain, salt
			if kind == "salt" {
				flag, target, untouched = "-s", salt, plain
			}
			before, err := os.ReadFile(untouched)
			if err != nil {
				t.Fatal(err)
			}
			requireCLISuccess(t, dir, "dict-add", flag, "str:added", "-R")
			after, err := os.ReadFile(untouched)
			if err != nil || string(before) != string(after) {
				t.Fatalf("unrequested dictionary changed: %v", err)
			}
			before, err = os.ReadFile(target)
			if err != nil || !strings.Contains(string(before), "added\n") {
				t.Fatalf("input not appended: %q, %v", before, err)
			}
			// A different spelling of the same path must not append a file to itself.
			requireCLISuccess(t, dir, "dict-add", flag, "file:./decipher_db/builtin-"+kind+".txt", "-R")
			after, err = os.ReadFile(target)
			if err != nil || string(before) != string(after) {
				t.Fatalf("self append modified dictionary: %v", err)
			}
			requireNoTemporaryDicts(t, dir)
		})
	}
}

func TestCLIDictionaryAppendWithoutFinalNewline(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "decipher_db/builtin-plain.txt", "original")
	requireCLISuccess(t, dir, "dict-add", "-p", "str:next", "-p", "str:last", "-R")
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "original\nnext\nlast\n" {
		t.Fatalf("dictionary entries merged: %q, %v", data, err)
	}
}

func TestCLIPredbThenDecryptAndCachedResult(t *testing.T) {
	dir := t.TempDir()
	plain := "integration-dictionary-password"
	hash := fmt.Sprintf("%x", md5.Sum([]byte(plain)))
	requireCLISuccess(t, dir, "dict-add", "-p", "str:"+plain, "-R")
	requireCLISuccess(t, dir, "predb-init", "-a", "md5($pass)", "-A", "-R")
	out := requireCLISuccess(t, dir, "dec", "-i", "str:"+hash, "-p", "str:wrong", "-a", "md5($pass)", "-A", "-O", "json", "-R")
	if !strings.Contains(out, "Starting predb crack") {
		t.Fatalf("predb path was not exercised: %s", out)
	}
	results := readJSONResults[cracker.CrackerResult](t, dir, "decipher.dec.json")
	if len(results) != 1 || results[0].Hash != hash || results[0].Plaintext != plain {
		t.Fatalf("predb did not recover original plaintext: %#v", results)
	}
	cache := filepath.Join(dir, "decipher_db", "success.cache")
	before, err := os.ReadFile(cache)
	if err != nil {
		t.Fatal(err)
	}
	out = requireCLISuccess(t, dir, "dec", "-i", "str:"+hash, "-p", "str:wrong-again", "-a", "md5($pass)", "-A", "--npc", "-O", "json", "-R")
	if !strings.Contains(out, "Result Cached") {
		t.Fatalf("success cache was not used: %s", out)
	}
	results = readJSONResults[cracker.CrackerResult](t, dir, "decipher.dec.json")
	if len(results) != 1 || results[0].Plaintext != plain {
		t.Fatalf("cached plaintext lost: %#v", results)
	}
	after, err := os.ReadFile(cache)
	if err != nil || string(before) != string(after) {
		t.Fatalf("cache hit appended duplicate records: %v", err)
	}
	requireNoTemporaryDicts(t, dir)
}

func TestCLISaltedTargetWithCustomSeparator(t *testing.T) {
	dir := t.TempDir()
	plain, salt := "password", "pepper"
	hash := fmt.Sprintf("%x", md5.Sum([]byte(salt+plain)))
	requireCLISuccess(t, dir, "dec", "-i", "str:"+hash+"|"+salt, "--concat-symbol", "|", "-p", "str:"+plain, "-a", "md5($salt.$pass)", "-A", "-O", "json", "-R")
	results := readJSONResults[cracker.CrackerResult](t, dir, "decipher.dec.json")
	if len(results) != 1 || results[0].Hash != hash || results[0].Plaintext != plain || results[0].Salt != salt {
		t.Fatalf("salted target was not recovered correctly: %#v", results)
	}
}

func TestCLIReversibleEncryptionRoundTrip(t *testing.T) {
	dir := t.TempDir()
	plain := "中文:comma,quoted\""
	path := writeFixture(t, dir, "input with spaces.txt", plain+"\n")
	requireCLISuccess(t, dir, "enc", "-p", "file:"+path, "-a", "base64($pass)", "-A", "-O", "json", "-R")
	enc := readJSONResults[cracker.EncryptResult](t, dir, "decipher.enc.json")
	if len(enc) != 1 || enc[0].Hash != base64.StdEncoding.EncodeToString([]byte(plain)) {
		t.Fatalf("incorrect reversible encryption: %#v", enc)
	}
	requireCLISuccess(t, dir, "dec", "-i", "str:"+enc[0].Hash, "-p", "str:irrelevant", "-a", "base64($pass)", "-A", "-O", "json", "-R")
	dec := readJSONResults[cracker.CrackerResult](t, dir, "decipher.dec.json")
	if len(dec) != 1 || dec[0].Plaintext != plain || dec[0].Algorithm != "base64($pass)" {
		t.Fatalf("reversible round trip failed: %#v", dec)
	}
	requireNoTemporaryDicts(t, dir)
}

func TestCLIIdentifyMultipleTargets(t *testing.T) {
	dir := t.TempDir()
	second := fmt.Sprintf("%x", sha1.Sum([]byte("password")))
	path := writeFixture(t, dir, "hashes.txt", testHash+"\n"+second+"\n")
	requireCLISuccess(t, dir, "id", "-i", "file:"+path, "-O", "json", "-R")
	results := readJSONResults[cracker.IdentResult](t, dir, "decipher.id.json")
	got := make(map[string][]string)
	for _, result := range results {
		got[result.Hash] = result.AlgosNames
	}
	if len(results) != 2 {
		t.Fatalf("identification lost targets: %#v", results)
	}
	for hash, name := range map[string]string{testHash: "md5($pass)", second: "sha1($pass)"} {
		found := false
		for _, algorithm := range got[hash] {
			if algorithm == name {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing expected identification %s: %#v", name, results)
		}
	}
	requireNoTemporaryDicts(t, dir)
}

func TestCLIOutputFormatsDoNotClobberEachOther(t *testing.T) {
	dir := t.TempDir()
	requireCLISuccess(t, dir, "enc", "-p", "str:first", "-a", "md5($pass)", "-A", "-R")
	path := filepath.Join(dir, "decipher.enc.csv")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(before))).ReadAll()
	if err != nil || len(rows) != 2 || len(rows[1]) != 4 || rows[1][3] != "first" {
		t.Fatalf("default output is not CSV: %q, %v", rows, err)
	}
	requireCLISuccess(t, dir, "enc", "-p", "str:second", "-a", "md5($pass)", "-A", "-O", "json", "-R")
	results := readJSONResults[cracker.EncryptResult](t, dir, "decipher.enc.json")
	if len(results) != 1 || results[0].Plaintext != "second" {
		t.Fatalf("incorrect JSON output: %#v", results)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatalf("JSON export clobbered CSV output: %v", err)
	}
}
