package main

import (
	"crypto/md5"
	"decipher/internal/cracker"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/winezer0/xutils/hashutils"
)

func calculationHash(plain string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(plain)))
}

func requireCalculationResults(t *testing.T, dir string, want ...cracker.CrackerResult) {
	t.Helper()
	got := readJSONResults[cracker.CrackerResult](t, dir, "decipher.dec.json")
	toSet := func(results []cracker.CrackerResult) map[cracker.CrackerResult]bool {
		set := make(map[cracker.CrackerResult]bool)
		for _, result := range results {
			set[result] = true
		}
		return set
	}
	if !reflect.DeepEqual(toSet(got), toSet(want)) || len(got) != len(want) {
		t.Fatalf("results mismatch: got %#v, want %#v", got, want)
	}
}

func calculatedResult(hash, algorithm, plain, salt string) cracker.CrackerResult {
	return cracker.CrackerResult{Hash: hash, Algorithm: algorithm, Plaintext: plain, Salt: salt, AlgoType: "static"}
}

func TestCLIIgnoresLegacyCalculationFiles(t *testing.T) {
	for name, contents := range map[string]string{
		"negative":           `{":123456":""}`,
		"incorrect positive": `{":123456":"md5($pass):incorrect:"}`,
		"invalid JSON":       "{broken",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			// Use the former filename formula so this fixture would have been loaded.
			filename := fmt.Sprintf("%s.%s.cache", hashutils.GetStrHashShort(testHash), hashutils.GetStrHash("md5($pass)"))
			path := writeFixture(t, dir, filepath.Join("decipher_cache", filename), contents)
			out := requireCLISuccess(t, dir, "dec", "-i", testHash, "-p", "str:123456", "-a", "md5($pass)", "-A", "--npc", "-O", "json", "-R")
			requireCalculationResults(t, dir, calculatedResult(testHash, "md5($pass)", "123456", ""))
			data, err := os.ReadFile(path)
			if err != nil || string(data) != contents {
				t.Fatalf("legacy file changed: %q, %v", data, err)
			}
			if strings.Contains(out, "load cache file error") || strings.Contains(out, "parse cache json error") {
				t.Fatalf("legacy file was read: %s", out)
			}
			files, err := filepath.Glob(filepath.Join(dir, "decipher_cache", "*.cache"))
			if err != nil || len(files) != 1 || files[0] != path {
				t.Fatalf("unexpected calculation files: %v, %v", files, err)
			}
		})
	}
}

func TestCLIMixedTargetsAndWorkerConsistency(t *testing.T) {
	plain := "mixed-password"
	unsalted := calculationHash(plain)
	first := calculationHash("salt-one" + plain)
	second := calculationHash("salt-two" + plain)
	missing := calculationHash("unavailable")
	want := []cracker.CrackerResult{
		calculatedResult(unsalted, "md5($pass)", plain, ""),
		calculatedResult(first, "md5($salt.$pass)", plain, "salt-one"),
		calculatedResult(second, "md5($salt.$pass)", plain, "salt-two"),
	}
	for _, workers := range []string{"1", "4"} {
		t.Run(workers, func(t *testing.T) {
			dir := t.TempDir()
			targets := writeFixture(t, dir, "targets.txt", unsalted+"\n"+first+":salt-one\n"+second+"\n"+missing+"\n")
			args := []string{"dec", "-i", "file:" + targets, "-p", "str:wrong,str:" + plain, "-s", "str:wrong-salt,str:salt-two",
				"-a", "md5($pass),md5($salt.$pass)", "-A", "--npc", "--workers", workers, "-O", "json", "-R"}
			requireCLISuccess(t, dir, args...)
			requireCalculationResults(t, dir, want...)
			data, err := os.ReadFile(filepath.Join(dir, "decipher.failure.csv"))
			if err != nil {
				t.Fatal(err)
			}
			rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
			if err != nil || len(rows) != 2 || rows[1][0] != missing {
				t.Fatalf("incorrect failure targets: %v, %v", rows, err)
			}
			requireNoCalculationCache(t, dir)
		})
	}
}

func TestCLIAffixCombinationsRecompute(t *testing.T) {
	for _, flags := range [][]string{
		{"--pp", "pass-prefix"}, {"--ps", "pass-suffix"},
		{"--sp", "salt-prefix"}, {"--ss", "salt-suffix"},
		{"--pp", "pass-prefix", "--ps", "pass-suffix", "--sp", "salt-prefix", "--ss", "salt-suffix"},
	} {
		t.Run(strings.Join(flags, " "), func(t *testing.T) {
			dir := t.TempDir()
			pass, salt := "password", "salt"
			for i := 0; i < len(flags); i += 2 {
				switch flags[i] {
				case "--pp":
					pass = flags[i+1] + pass
				case "--ps":
					pass += flags[i+1]
				case "--sp":
					salt = flags[i+1] + salt
				case "--ss":
					salt += flags[i+1]
				}
			}
			hash := calculationHash(salt + pass)
			args := []string{"dec", "-i", hash, "-p", "str:password", "-s", "str:salt", "-a", "md5($salt.$pass)", "-A", "--npc", "-O", "json", "-R"}
			requireCLISuccess(t, dir, args...)
			requireCalculationResults(t, dir)
			requireCLISuccess(t, dir, append(args, flags...)...)
			requireCalculationResults(t, dir, calculatedResult(hash, "md5($salt.$pass)", pass, "salt"))
			requireNoCalculationCache(t, dir)
		})
	}
}

func TestCLISuccessCacheAfterLiveCalculation(t *testing.T) {
	dir := t.TempDir()
	args := []string{"dec", "-i", testHash, "-a", "md5($pass)", "-A", "--npc", "-O", "json", "-R"}
	requireCLISuccess(t, dir, append(args, "-p", "str:123456")...)
	requireCalculationResults(t, dir, calculatedResult(testHash, "md5($pass)", "123456", ""))
	path := filepath.Join(dir, "decipher_db", cracker.SuccessCache)
	before, err := os.ReadFile(path)
	if err != nil || len(before) == 0 {
		t.Fatalf("success cache missing: %v", err)
	}
	out := requireCLISuccess(t, dir, append(args, "-p", "str:wrong")...)
	if !strings.Contains(out, "Result Cached") {
		t.Fatalf("success cache was not used: %s", out)
	}
	requireCalculationResults(t, dir, calculatedResult(testHash, "md5($pass)", "123456", ""))
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatalf("cache hit changed success records: %v", err)
	}
	requireNoCalculationCache(t, dir)
}

func TestCLIPredbCanBeSkippedForLiveCalculation(t *testing.T) {
	dir := t.TempDir()
	requireCLISuccess(t, dir, "dict", "init", "-p", "str:123456", "-a", "md5($pass)", "-A", "-R")
	args := []string{"dec", "-i", testHash, "-a", "md5($pass)", "-A", "-O", "json", "-R"}
	requireCLISuccess(t, dir, append(args, "-p", "str:wrong")...)
	results := readJSONResults[cracker.CrackerResult](t, dir, "decipher.dec.json")
	if len(results) != 1 || results[0].Hash != testHash || results[0].Algorithm != "md5($pass)" || results[0].Plaintext != "123456" || results[0].Salt != "" {
		t.Fatalf("predb miss: %#v", results)
	}
	if err := os.Remove(filepath.Join(dir, "decipher_db", cracker.SuccessCache)); err != nil {
		t.Fatal(err)
	}
	requireCLISuccess(t, dir, append(args, "--npc", "-p", "str:wrong")...)
	requireCalculationResults(t, dir)
	out := requireCLISuccess(t, dir, append(args, "--npc", "-p", "str:123456")...)
	if strings.Contains(out, "Starting predb crack") || strings.Contains(out, "Result Cached") {
		t.Fatalf("unexpected cache path: %s", out)
	}
	requireCalculationResults(t, dir, calculatedResult(testHash, "md5($pass)", "123456", ""))
}

func TestCLIAlgorithmChangesAndMultipleDictionaries(t *testing.T) {
	dir := t.TempDir()
	wrong := writeFixture(t, dir, "first.txt", "wrong\n")
	correct := writeFixture(t, dir, "second.txt", "123456\n")
	args := []string{"dec", "-i", testHash, "-p", "file:" + wrong, "-p", "file:" + correct, "-A", "--npc", "-O", "json", "-R"}
	requireCLISuccess(t, dir, append(args, "-a", "md5(md5($pass))")...)
	requireCalculationResults(t, dir)
	requireCLISuccess(t, dir, append(args, "-a", "md5($pass)")...)
	requireCalculationResults(t, dir, calculatedResult(testHash, "md5($pass)", "123456", ""))
	requireNoCalculationCache(t, dir)
}

func TestCLICustomTemporaryDirectoryLifecycle(t *testing.T) {
	for _, outcome := range []string{"success", "failure"} {
		for _, remove := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/remove=%t", outcome, remove), func(t *testing.T) {
				dir := t.TempDir()
				cacheDir := filepath.Join(dir, "temporary dictionaries")
				marker := writeFixture(t, dir, filepath.Join("temporary dictionaries", "keep.txt"), "keep")
				args := []string{"dec", "-i", testHash, "-p", "str:123456", "-a", "md5($pass)", "-A", "--npc", "--run-cache-dir", cacheDir, "-O", "json"}
				if remove {
					args = append(args, "-R")
				}
				if outcome == "failure" {
					// Fail after dictionaries have been created and calculation completed.
					writeFixture(t, dir, "blocked", "not a directory")
					args = append(args, "-o", "blocked")
				}
				out, code := runCLI(t, dir, args...)
				wantCode := 0
				if outcome == "failure" {
					wantCode = 1
				}
				if code != wantCode {
					t.Fatalf("exit %d, want %d: %s", code, wantCode, out)
				}
				if outcome == "failure" && !strings.Contains(out, "export results") {
					t.Fatalf("did not reach output failure: %s", out)
				}
				if outcome == "success" {
					requireCalculationResults(t, dir, calculatedResult(testHash, "md5($pass)", "123456", ""))
				}
				files, err := filepath.Glob(filepath.Join(cacheDir, "decipher_*.txt"))
				if err != nil || (remove && len(files) != 0) || (!remove && len(files) < 2) {
					t.Fatalf("incorrect temporary files: %v, %v", files, err)
				}
				if data, err := os.ReadFile(marker); err != nil || string(data) != "keep" {
					t.Fatalf("unrelated file changed: %v", err)
				}
				requireMissing(t, filepath.Join(dir, "decipher_cache"))
			})
		}
	}
}
