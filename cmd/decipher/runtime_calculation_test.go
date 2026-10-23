package main

import (
	"crypto/md5"
	"github.com/winezer0/decipher/internal/cracker"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func requireNoCalculationCache(t *testing.T, dir string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "decipher_cache", "*.cache"))
	if err != nil || len(files) != 0 {
		t.Fatalf("calculation cache files: %v, %v", files, err)
	}
}

func TestCLIRecomputesAfterAffixChange(t *testing.T) {
	dir := t.TempDir()
	hash := fmt.Sprintf("%x", md5.Sum([]byte("prefix123456")))
	args := []string{"dec", "-i", hash, "-p", "str:123456", "-a", "md5($pass)", "-A", "--npc", "-O", "json", "-R"}
	requireCLISuccess(t, dir, args...)
	if results := readJSONResults[cracker.CrackerResult](t, dir, "decipher.dec.json"); len(results) != 0 {
		t.Fatalf("unexpected match before prefix: %#v", results)
	}
	requireCLISuccess(t, dir, append(args, "--pp", "prefix")...)
	results := readJSONResults[cracker.CrackerResult](t, dir, "decipher.dec.json")
	if len(results) != 1 || results[0].Plaintext != "prefix123456" || results[0].Hash != hash {
		t.Fatalf("incorrect recomputed result: %#v", results)
	}
	requireNoCalculationCache(t, dir)
}

func TestCLIRepeatedCalculationPreservesColon(t *testing.T) {
	dir := t.TempDir()
	hash := fmt.Sprintf("%x", md5.Sum([]byte("a:b")))
	for attempt := 0; attempt < 2; attempt++ {
		requireCLISuccess(t, dir, "dec", "-i", hash, "-p", "str:a:b", "-a", "md5($pass)", "-A", "--npc", "-O", "json", "-R")
		results := readJSONResults[cracker.CrackerResult](t, dir, "decipher.dec.json")
		if len(results) != 1 || results[0].Plaintext != "a:b" || results[0].Salt != "" || results[0].AlgoType != "static" {
			t.Fatalf("attempt %d: incorrect result: %#v", attempt, results)
		}
		if err := os.Remove(filepath.Join(dir, "decipher_db", cracker.SuccessCache)); err != nil {
			t.Fatal(err)
		}
	}
	requireNoCalculationCache(t, dir)
}

func TestCLILargeDictionaryCalculation(t *testing.T) {
	for _, workers := range []string{"1", "4"} {
		t.Run(workers, func(t *testing.T) {
			dir := t.TempDir()
			var dictionary strings.Builder
			for i := 0; i < 10050; i++ {
				fmt.Fprintf(&dictionary, "candidate-%d\n", i)
			}
			path := filepath.Join(dir, "candidates.txt")
			if err := os.WriteFile(path, []byte(dictionary.String()), 0600); err != nil {
				t.Fatal(err)
			}
			hash := fmt.Sprintf("%x", md5.Sum([]byte("candidate-10049")))
			requireCLISuccess(t, dir, "dec", "-i", hash, "-p", "file:"+path, "-a", "md5($pass)", "-A", "--npc", "--workers", workers, "-O", "json", "-R")
			results := readJSONResults[cracker.CrackerResult](t, dir, "decipher.dec.json")
			if len(results) != 1 || results[0].Plaintext != "candidate-10049" || results[0].Hash != hash {
				t.Fatalf("incorrect large dictionary result: %#v", results)
			}
			requireNoCalculationCache(t, dir)
		})
	}
}
