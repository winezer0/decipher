package main

import (
	"context"
	"crypto/md5"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testHash = "e10adc3949ba59abbe56e057f20f883e"

// 使用独立进程测试真实 main、os.Exit 和参数解析，避免测试进程被退出。
func TestCLIProcess(t *testing.T) {
	if os.Getenv("DECIPHER_CLI_TEST_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{AppName}, os.Args[i+1:]...)
			main()
		}
	}
	os.Exit(99)
}

func runCLI(t *testing.T, dir string, args ...string) (string, int) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, append([]string{"-test.run=^TestCLIProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "DECIPHER_CLI_TEST_HELPER=1")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("CLI timed out: %v", args)
	}
	if err == nil {
		return string(out), 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatal(err)
	}
	return string(out), exitErr.ExitCode()
}

func writeFixture(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no file at %s, got %v", path, err)
	}
}

func TestCLIRejectsInvalidArgumentsBeforeSideEffects(t *testing.T) {
	for _, args := range [][]string{
		{"typo"}, {"--unknown-option"}, {"dict"}, {"dict", "typo"}, {"dict", "add"}, {"dict", "init"},
		{"enc", "dec"},
		{"-i", "str:" + testHash}, {"enc", "-i", "str:" + testHash},
		{"id", "-p", "str:123456"}, {"dict-add", "-a", "md5"},
		{"predb-init", "-O", "json"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			dir := t.TempDir()
			marker := writeFixture(t, dir, "decipher_db/marker", "keep")
			out, code := runCLI(t, dir, append([]string{"--cc"}, args...)...)
			if code != 1 {
				t.Fatalf("exit %d: %s", code, out)
			}
			if data, err := os.ReadFile(marker); err != nil || string(data) != "keep" {
				t.Fatalf("invalid mode changed cache: %v", err)
			}
			requireMissing(t, filepath.Join(dir, "decipher_db", "builtin-plain.txt"))
			requireMissing(t, filepath.Join(dir, "decipher_cache"))
		})
	}
}

func TestCLIRejectsInvalidOutputFormat(t *testing.T) {
	dir := t.TempDir()
	out, code := runCLI(t, dir, "enc", "-p", "str:123456", "-O", "yaml")
	if code != 1 || !strings.Contains(out, "yaml") {
		t.Fatalf("exit %d: %s", code, out)
	}
	requireMissing(t, filepath.Join(dir, "decipher_db"))
}

func TestCLIMissingExplicitFileNeverFallsBack(t *testing.T) {
	cases := [][]string{
		{"id", "-i", "file:missing.txt"},
		{"enc", "-p", "file:missing.txt"},
		{"dec", "-i", "str:" + testHash, "-p", "file:missing.txt"},
		{"predb-init", "-p", "file:missing.txt"},
		{"enc", "-p", "str:123456", "-s", "file:missing.txt"},
		{"predb-init", "-p", "file:existing.txt", "-s", "file:missing.txt"},
		{"dict-add", "-p", "file:missing.txt"},
		{"enc", "-p", "file:."},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			dir := t.TempDir()
			writeFixture(t, dir, "existing.txt", "123456\n")
			out, code := runCLI(t, dir, args...)
			if code != 1 || !strings.Contains(out, "input file") || strings.Contains(out, "use builtin plain dicts") {
				t.Fatalf("exit %d: %s", code, out)
			}
			requireMissing(t, filepath.Join(dir, "decipher_db"))
			requireMissing(t, filepath.Join(dir, "decipher_cache"))
		})
	}
}

func TestCLIReportsActionAndExportFailures(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"encrypt output", []string{"enc", "-p", "str:123456", "-o", "blocked"}},
		{"identify CSV output", []string{"id", "-i", "str:" + testHash, "-o", "blocked"}},
		{"identify JSON output", []string{"id", "-i", "str:" + testHash, "-O", "json", "-o", "blocked"}},
		{"decrypt CSV output", []string{"dec", "-i", "str:" + testHash, "-p", "str:123456", "--npc", "-o", "blocked"}},
		{"decrypt JSON output", []string{"dec", "-i", "str:" + testHash, "-p", "str:123456", "--npc", "-o", "blocked", "-O", "json"}},
		{"no algorithms", []string{"enc", "-p", "str:123456", "-a", "not-an-algorithm"}},
		{"bad generator", []string{"dec", "-i", "str:" + testHash, "-p", "gen:invalid"}},
		{"no input", []string{"dec"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFixture(t, dir, "blocked", "not a directory")
			args := append(tc.args, "-a", "md5($pass)", "-A")
			if tc.args[0] == "id" {
				args = tc.args
			}
			if tc.name == "no algorithms" {
				args = append(tc.args, "-A")
			}
			out, code := runCLI(t, dir, args...)
			if code != 1 || !strings.Contains(out, "failed:") || strings.Contains(out, " completed") {
				t.Fatalf("exit %d: %s", code, out)
			}
		})
	}
}

func TestCLICacheWriteErrorsAreFailures(t *testing.T) {
	for _, cache := range []string{"success", "failure"} {
		t.Run(cache, func(t *testing.T) {
			dir := t.TempDir()
			args := []string{"dec", "-i", "str:" + testHash, "-a", "md5($pass)", "-A", "--npc"}
			if cache == "success" {
				if err := os.MkdirAll(filepath.Join(dir, "decipher_db", "success.cache"), 0755); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-p", "str:123456")
			} else {
				args = append(args, "-p", "str:wrong", "--failure-cache", ".")
			}
			out, code := runCLI(t, dir, args...)
			if code != 1 || !strings.Contains(out, "write "+cache) || strings.Contains(out, "decrypt completed") {
				t.Fatalf("exit %d: %s", code, out)
			}
		})
	}
}

func TestCLIPredbWriteErrorsAreFailures(t *testing.T) {
	for _, mode := range []string{"predb-init", "dec"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			blocked := filepath.Join(dir, "decipher_db", "cache_md5($pass).predb")
			if err := os.MkdirAll(blocked, 0755); err != nil {
				t.Fatal(err)
			}
			args := []string{"dec", "-i", "str:" + testHash, "-p", "str:123456", "-a", "md5($pass)", "-A"}
			if mode == "predb-init" {
				args = []string{"predb-init", "-p", "str:123456", "-a", "md5($pass)", "-A"}
			}
			out, code := runCLI(t, dir, args...)
			if code != 1 || !strings.Contains(out, "open pre-db") || strings.Contains(out, " completed") {
				t.Fatalf("exit %d: %s", code, out)
			}
		})
	}
}

func TestCLIMaintenanceExitsWithoutInitializingEngine(t *testing.T) {
	for _, flags := range [][]string{{"--cc"}, {"--dc"}, {"--cc", "--dc"}} {
		t.Run(strings.Join(flags, " "), func(t *testing.T) {
			dir := t.TempDir()
			cache := writeFixture(t, dir, "decipher_db/cache_test.predb", "one\none\ntwo\n")
			writeFixture(t, dir, "decipher_cache/marker", "cache")
			failure := writeFixture(t, dir, "decipher.failure.csv", "failures")
			// 即使提供模式，也只执行维护，不继续计算。
			args := append(flags, "enc", "-p", "str:123456")
			out, code := runCLI(t, dir, args...)
			if code != 0 || strings.Contains(out, "running command") {
				t.Fatalf("exit %d: %s", code, out)
			}
			requireMissing(t, filepath.Join(dir, "decipher_db", "builtin-plain.txt"))
			requireMissing(t, filepath.Join(dir, "decipher.enc.csv"))
			if flags[0] == "--cc" {
				requireMissing(t, filepath.Join(dir, "decipher_db"))
				requireMissing(t, filepath.Join(dir, "decipher_cache"))
				requireMissing(t, failure)
			} else {
				data, err := os.ReadFile(cache)
				if err != nil || strings.Count(string(data), "one") != 1 || !strings.Contains(string(data), "two") {
					t.Fatalf("deduplication failed: %q, %v", data, err)
				}
			}
		})
	}
	for _, flag := range []string{"--cc", "--dc"} {
		t.Run(flag+" absent", func(t *testing.T) {
			dir := t.TempDir()
			out, code := runCLI(t, dir, flag)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, out)
			}
			requireMissing(t, filepath.Join(dir, "decipher_db"))
			requireMissing(t, filepath.Join(dir, "decipher_cache"))
		})
	}
}

func TestCLIDeduplicationErrorIsFailure(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "blocked", "not a directory")
	out, code := runCLI(t, dir, "--dc", "--predb-dir", "blocked")
	if code != 1 || !strings.Contains(out, "read cache directory") {
		t.Fatalf("exit %d: %s", code, out)
	}
}

func TestCLIMultipleCommandsRejectedBeforeExecution(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "decipher.id.csv/marker", "keep")
	out, code := runCLI(t, dir, "enc", "id", "-p", "str:123456")
	if code != 1 || strings.Contains(out, "running command") {
		t.Fatalf("exit %d: %s", code, out)
	}
	requireMissing(t, filepath.Join(dir, "decipher.enc.csv"))
}

func TestCLIEncryptFormatsPreserveFields(t *testing.T) {
	plain, salt := "中文:plain,\"quoted\"", "salt:盐,\"quoted\""
	algorithm := "md5($salt.$pass)"
	hash := fmt.Sprintf("%x", md5.Sum([]byte(salt+plain)))
	for _, format := range []string{"csv", "json"} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			writeFixture(t, dir, "plains.txt", plain+"\n")
			writeFixture(t, dir, "salts.txt", salt+"\n")
			out, code := runCLI(t, dir, "enc", "-p", "file:plains.txt", "-s", "file:salts.txt", "-a", algorithm, "-A", "-O", format)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, out)
			}
			data, err := os.ReadFile(filepath.Join(dir, "decipher.enc."+format))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			if format == "json" {
				var records []map[string]string
				if err := json.Unmarshal(data, &records); err != nil {
					t.Fatal(err)
				}
				for _, r := range records {
					if r["salt"] == salt && r["plaintext"] == plain && r["algorithm"] == algorithm && r["hash"] == hash {
						found = true
					}
				}
			} else {
				rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
				if err != nil {
					t.Fatal(err)
				}
				for _, r := range rows[1:] {
					if len(r) == 4 && r[0] == algorithm && r[1] == hash && r[2] == salt && r[3] == plain {
						found = true
					}
				}
			}
			if !found {
				t.Fatalf("missing complete record: %s", data)
			}
		})
	}
}

func TestCLIOutputDirectories(t *testing.T) {
	for _, mode := range []string{"id", "enc", "dec"} {
		for _, format := range []string{"csv", "json"} {
			for _, explicit := range []bool{false, true} {
				t.Run(mode+"/"+format+"/"+map[bool]string{false: "default", true: "explicit"}[explicit], func(t *testing.T) {
					dir := t.TempDir()
					outputDir := dir
					args := []string{mode, "-O", format}
					if mode == "id" || mode == "dec" {
						args = append(args, "-i", "str:"+testHash)
					}
					if mode == "enc" || mode == "dec" {
						args = append(args, "-p", "str:123456", "-a", "md5($pass)", "-A")
					}
					if mode == "dec" {
						args = append(args, "--npc")
					}
					if explicit {
						outputDir = filepath.Join(dir, "results with spaces")
						if err := os.Mkdir(outputDir, 0755); err != nil {
							t.Fatal(err)
						}
						args = append(args, "-o", outputDir)
					}
					name := "decipher." + mode + "." + format
					if err := os.WriteFile(filepath.Join(outputDir, name), []byte("old-result-marker\n"), 0644); err != nil {
						t.Fatal(err)
					}
					out, code := runCLI(t, dir, args...)
					if code != 0 {
						t.Fatalf("exit %d: %s", code, out)
					}
					data, err := os.ReadFile(filepath.Join(outputDir, name))
					if err != nil || !strings.Contains(string(data), testHash) || strings.Contains(string(data), "old-result-marker") {
						t.Fatalf("invalid output %s: %q, %v", name, data, err)
					}
					if mode == "id" {
						if format == "json" {
							if !json.Valid(data) {
								t.Fatalf("invalid JSON: %s", data)
							}
						} else if rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll(); err != nil || len(rows) != 2 || rows[1][0] != testHash {
							t.Fatalf("invalid CSV: %q, %v", rows, err)
						}
					}
					if explicit {
						requireMissing(t, filepath.Join(dir, name))
					}
				})
			}
		}
	}
}

func TestCLIValidInputs(t *testing.T) {
	cases := [][]string{
		{"enc", "-p", "str:123456"},
		{"enc", "-p", "file:words.txt"},
		{"enc", "-p", "123456"},
		{"dec", "-i", "str:" + testHash, "-p", "file:words.txt", "--npc"},
		{"dec", "-i", "str:" + testHash, "--npc"},
		{"predb-init", "-p", "file:words.txt"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			dir := t.TempDir()
			writeFixture(t, dir, "words.txt", "123456\n")
			out, code := runCLI(t, dir, append(args, "-a", "md5($pass)", "-A", "-R")...)
			if len(args) > 0 && args[0] == "predb-init" {
				data, err := os.ReadFile(filepath.Join(dir, "decipher_db", "cache_md5($pass).predb"))
				if err != nil {
					t.Fatal(err)
				}
				out += string(data)
			}
			if code != 0 || !strings.Contains(out, testHash) {
				t.Fatalf("exit %d: %s", code, out)
			}
		})
	}
}
