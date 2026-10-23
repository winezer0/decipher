package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLITemporaryFilesOnFailure(t *testing.T) {
	cases := [][]string{
		{"enc", "-p", "str:123456", "-s", "gen:invalid"},
		{"enc", "-p", "str:123456", "-o", "blocked"},
		{"dec", "-i", "str:" + testHash, "-p", "str:123456", "-s", "gen:invalid"},
		{"id", "-i", "str:" + testHash, "-i", "gen:invalid"},
		{"id", "-i", "str:" + testHash, "-o", "blocked"},
		{"predb-init", "-p", "str:123456", "-s", "gen:invalid"},
		{"dict-add", "-p", "str:123456", "-s", "gen:invalid"},
	}
	for _, args := range cases {
		for _, remove := range []bool{false, true} {
			t.Run(strings.Join(args, " ")+map[bool]string{false: "/keep", true: "/remove"}[remove], func(t *testing.T) {
				dir := t.TempDir()
				writeFixture(t, dir, "blocked", "not a directory")
				marker := writeFixture(t, dir, "decipher_cache/user.txt", "keep")
				cliArgs := append([]string{}, args...)
				if args[0] != "id" && args[0] != "dict-add" {
					cliArgs = append(cliArgs, "-a", "md5($pass)", "-A")
				}
				if remove {
					cliArgs = append(cliArgs, "-R")
				}
				out, code := runCLI(t, dir, cliArgs...)
				if code != 1 {
					t.Fatalf("exit %d: %s", code, out)
				}
				files, err := filepath.Glob(filepath.Join(dir, "decipher_cache", "decipher_*.txt"))
				if err != nil || (len(files) == 0) != remove {
					t.Fatalf("unexpected temporary files: %v, %v", files, err)
				}
				if data, err := os.ReadFile(marker); err != nil || string(data) != "keep" {
					t.Fatalf("user file changed: %v", err)
				}
			})
		}
	}
}

func TestTemporaryCleanupReportsErrorsAndContinues(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "blocked/child", "keep")
	file := writeFixture(t, dir, "temporary", "remove")
	original := errors.New("action failed")
	result := original
	temps := tempFiles{remove: true, paths: []string{filepath.Join(dir, "blocked"), file, filepath.Join(dir, "absent")}}
	temps.cleanup(&result)
	if !errors.Is(result, original) || !strings.Contains(result.Error(), "remove temporary file") {
		t.Fatalf("missing combined error: %v", result)
	}
	requireMissing(t, file)
	result = nil
	temps.cleanup(&result)
	if result == nil {
		t.Fatal("cleanup failure must also fail a successful action")
	}
}

func TestCLIWorkersValidation(t *testing.T) {
	dir := t.TempDir()
	marker := writeFixture(t, dir, "decipher_db/marker", "keep")
	out, code := runCLI(t, dir, "--cc", "enc", "--workers=-1")
	if code != 1 || !strings.Contains(out, "workers must be >= 0") {
		t.Fatalf("exit %d: %s", code, out)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("invalid workers triggered maintenance: %v", err)
	}
	for _, workers := range []string{"0", "1", "2"} {
		dir := t.TempDir()
		out, code := runCLI(t, dir, "enc", "-p", "str:123456", "-a", "md5($pass)", "-A", "-w", workers, "-R")
		if code != 0 {
			t.Fatalf("workers %s exit %d: %s", workers, code, out)
		}
		files, _ := filepath.Glob(filepath.Join(dir, "decipher_cache", "decipher_*.txt"))
		if len(files) != 0 {
			t.Fatalf("successful action retained temporary files: %v", files)
		}
	}
}
