package main

import (
	"crypto/md5"
	"github.com/winezer0/decipher/internal/cracker"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIEncryptLargeStream(t *testing.T) {
	for _, format := range []string{"csv", "json"} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			var plains strings.Builder
			want := make(map[cracker.EncryptResult]bool)
			for i := 0; i < 300; i++ {
				plain := fmt.Sprintf("文本,\"-%d", i)
				fmt.Fprintln(&plains, plain)
				want[cracker.EncryptResult{Algorithm: "md5($pass)", Hash: fmt.Sprintf("%x", md5.Sum([]byte(plain))), Plaintext: plain}] = true
				for _, salt := range []string{"", "a", "aa", "ab", "b", "ba", "bb"} {
					want[cracker.EncryptResult{Algorithm: "md5($salt.$pass)", Hash: fmt.Sprintf("%x", md5.Sum([]byte(salt+plain))), Salt: salt, Plaintext: plain}] = true
				}
			}
			writeFixture(t, dir, "plains", plains.String())
			path := filepath.Join(dir, "decipher.enc."+format)
			writeFixture(t, dir, "decipher.enc."+format, "old-result-marker")
			out, code := runCLI(t, dir, "enc", "--workers", "4", "-p", "file:plains", "-s", "gen:1:2:ab", "-a", "md5($pass),md5($salt.$pass)", "-A", "-O", format)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, out)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var got []cracker.EncryptResult
			if format == "json" {
				if err := json.Unmarshal(data, &got); err != nil {
					t.Fatal(err)
				}
			} else {
				rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range rows[1:] {
					got = append(got, cracker.EncryptResult{Algorithm: row[0], Hash: row[1], Salt: row[2], Plaintext: row[3]})
				}
			}
			if len(got) != len(want) {
				t.Fatalf("got %d, want %d", len(got), len(want))
			}
			for _, result := range got {
				if !want[result] {
					t.Fatalf("unexpected or duplicate result: %+v", result)
				}
				delete(want, result)
				if strings.Contains(out, result.String()) {
					t.Fatal("large result set printed to console")
				}
			}
		})
	}
}

func TestCLIEncryptSmallPreview(t *testing.T) {
	out, code := runCLI(t, t.TempDir(), "enc", "-p", "str:123456", "-a", "md5($pass)", "-A")
	if code != 0 || !strings.Contains(out, "md5($pass):"+testHash+"::123456") {
		t.Fatalf("missing preview: exit %d %s", code, out)
	}
}

func TestCLIEncryptRejectsOutputAsInput(t *testing.T) {
	for _, inputFlag := range []string{"-p", "-s"} {
		t.Run(inputFlag, func(t *testing.T) {
			dir := t.TempDir()
			path := writeFixture(t, dir, "decipher.enc.csv", "original-input\n")
			args := []string{"enc", "-a", "md5($salt.$pass)", "-A", inputFlag, "file:" + path}
			if inputFlag == "-s" {
				args = append(args, "-p", "str:plain")
			}
			out, code := runCLI(t, dir, args...)
			if code == 0 || !strings.Contains(out, "also an input dictionary") {
				t.Fatalf("exit %d: %s", code, out)
			}
			if data, err := os.ReadFile(path); err != nil || string(data) != "original-input\n" {
				t.Fatalf("input changed: %q %v", data, err)
			}
		})
	}
}

func TestEncryptOutputHardlinkInput(t *testing.T) {
	dir := t.TempDir()
	source := writeFixture(t, dir, "source", "keep")
	output := filepath.Join(dir, "output")
	if err := os.Link(source, output); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if err := checkEncryptOutputInputs(output, []string{source}); err == nil {
		t.Fatal("hardlinked input accepted")
	}
}
