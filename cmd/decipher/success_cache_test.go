package main

import (
	"github.com/winezer0/decipher/internal/cracker"
	"github.com/winezer0/decipher/internal/export"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLISelectedSuccessCacheKeepsLastRecord(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "decipher_db/success.cache", "")
	last := calculatedResult(strings.ToUpper(testHash), "md5($pass)", "123456", "")
	if err := export.ExportCSV(path, []cracker.CrackerResult{
		calculatedResult(testHash, "md5($pass)", "stale", ""),
		calculatedResult(calculationHash("unrelated"), "md5($pass)", "unrelated", ""),
		last,
	}, true); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := requireCLISuccess(t, dir, "dec", "-i", testHash, "-p", "str:wrong", "-a", "md5($pass)", "-A", "--npc", "-O", "json", "-R")
	if !strings.Contains(out, "Result Cached") {
		t.Fatalf("success cache was not used: %s", out)
	}
	requireCalculationResults(t, dir, last)
	after, err := os.ReadFile(filepath.Join(dir, "decipher_db", "success.cache"))
	if err != nil || string(after) != string(before) {
		t.Fatalf("cache hit changed file: %v", err)
	}
}
