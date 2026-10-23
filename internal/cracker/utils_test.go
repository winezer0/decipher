package cracker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	utils "github.com/winezer0/xutils/fileutils"
)

func dictionaryTestFile(t testing.TB, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dictionary.txt")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCleanDictionaryLineUnicodeCompatibility(t *testing.T) {
	var chunk strings.Builder
	check := func() {
		line := chunk.String()
		if got, want := cleanDictionaryLine(line), utils.CleanupUnprintableChars(line); got != want {
			t.Fatal("Unicode cleanup differs from original")
		}
		chunk.Reset()
	}
	for r := rune(0); r <= utf8.MaxRune; r++ {
		chunk.WriteRune(r)
		if r%4096 == 4095 {
			check()
		}
	}
	check()
}

func FuzzDictionaryLineCleanup(f *testing.F) {
	for _, line := range []string{"", "ascii", "中文\x00\u200b\ufeff", "\xff\xfe\xc0\xaf", "\x00 padded \x00"} {
		f.Add(line)
	}
	f.Fuzz(func(t *testing.T, line string) {
		if got, want := cleanDictionaryLine(line), utils.CleanupUnprintableChars(line); got != want {
			t.Fatalf("cleanup %q got %q want %q", line, got, want)
		}
	})
}

type failedDictionaryReader struct{ err error }

func (r failedDictionaryReader) Read(p []byte) (int, error) { return copy(p, "valid\n"), r.err }

func TestScanDictionaryLinesReadError(t *testing.T) {
	failure := errors.New("injected read error")
	var lines []string
	err := scanDictionaryLines(failedDictionaryReader{failure}, func(line string) { lines = append(lines, line) })
	if !errors.Is(err, failure) || !reflect.DeepEqual(lines, []string{"valid"}) {
		t.Fatalf("lines=%v err=%v", lines, err)
	}
}

func TestDictionaryResultsSurviveBufferReuse(t *testing.T) {
	var content strings.Builder
	var wantLines []string
	var wantTargets []HashSaltTarget
	for i := 0; i < 3000; i++ {
		line := fmt.Sprintf("hash-%06d:salt-%06d:", i, i) + strings.Repeat("ignored", 40)
		fmt.Fprintln(&content, line)
		wantLines = append(wantLines, line)
		wantTargets = append(wantTargets, HashSaltTarget{Hash: fmt.Sprintf("hash-%06d", i), Salt: fmt.Sprintf("salt-%06d", i)})
	}
	path := dictionaryTestFile(t, content.String())
	if got := ReadFilesToStrings([]string{path}, false); !reflect.DeepEqual(got, wantLines) {
		t.Fatal("lines changed after scanner buffer reuse")
	}
	if got := ParseFilesToTargets([]string{path}); !reflect.DeepEqual(got, wantTargets) {
		t.Fatal("targets changed after scanner buffer reuse")
	}
}

func TestDictionaryLineEndAndUTF8Boundaries(t *testing.T) {
	for _, end := range []string{"", "\n", "\r\n"} {
		line := strings.Repeat("x", DefaultScannerBufferSize-1) + "中文"
		if got := ReadFilesToStrings([]string{dictionaryTestFile(t, line+end)}, false); !reflect.DeepEqual(got, []string{line}) {
			t.Fatalf("UTF-8 or line ending %q changed", end)
		}
	}
	path := dictionaryTestFile(t, strings.Repeat(" ", maxDictionaryTokenSize-2)+"x")
	if got := ReadFilesToStrings([]string{path}, false); !reflect.DeepEqual(got, []string{"x"}) {
		t.Fatal("maximum accepted line without newline changed")
	}
	path = dictionaryTestFile(t, strings.Repeat(" ", maxDictionaryTokenSize-1)+"x")
	if got := ReadFilesToStrings([]string{path}, false); got != nil {
		t.Fatal("oversize line without newline accepted")
	}
}

func TestTargetLargeDiscardedTailWithCustomSeparators(t *testing.T) {
	old := ConcatSymbol
	t.Cleanup(func() { ConcatSymbol = old })
	for _, separator := range []string{":", "||", "盐"} {
		ConcatSymbol = separator
		line := "哈" + separator + "密钥" + separator + strings.Repeat("ignored", 1000)
		line += "\n哈" + separator + separator + strings.Repeat("ignored", 1000)
		got := ParseFilesToTargets([]string{dictionaryTestFile(t, line)})
		want := []HashSaltTarget{{Hash: "哈", Salt: "密钥"}, {Hash: "哈"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("separator=%q got %#v want %#v", separator, got, want)
		}
	}
	if got := ParseFilesToTargets([]string{dictionaryTestFile(t, " #comment\n\x00\n")}); got != nil {
		t.Fatalf("expected nil filtered targets: %#v", got)
	}
}

func TestReadFilesToStringsCompatibility(t *testing.T) {
	path := dictionaryTestFile(t, " \tfirst \r\n\nfirst\n\t中文\"逗,号\t\n\ufeffbom\n\x00  padded  \x00\nA\x01B\u200bC\u200fD\x7fE\u0085F\ninvalid\xff\xfe\nlast")
	for _, trims := range []bool{false, true} {
		want := []string{"first", "first", "中文\"逗,号", "\ufeffbom", "  padded  ", "ABCDEF", "invalid\ufffd\ufffd", "last"}
		if trims {
			want[4] = "padded"
		}
		if got := ReadFilesToStrings([]string{path}, trims); !reflect.DeepEqual(got, want) {
			t.Fatalf("trims=%t: got %#v, want %#v", trims, got, want)
		}
	}
	for _, inputs := range [][]string{nil, {dictionaryTestFile(t, "\n \t\r\n")}, {filepath.Join(t.TempDir(), "missing")}, {t.TempDir()}} {
		if got := ReadFilesToStrings(inputs, false); got != nil {
			t.Fatalf("expected nil, got %#v", got)
		}
	}
	other := dictionaryTestFile(t, "second\nfirst\n")
	if got := ReadFilesToStrings([]string{other, other}, false); !reflect.DeepEqual(got, []string{"second", "first", "second", "first"}) {
		t.Fatalf("duplicates or order changed: %#v", got)
	}
}

func TestDictionaryScannerBoundariesAndRollback(t *testing.T) {
	const max = 10 * 1024 * 1024
	for _, size := range []int{64*1024 - 1, 64 * 1024, 1024*1024 + 1, max - 1} {
		path := dictionaryTestFile(t, strings.Repeat(" ", size-1)+"x\n")
		if got := ReadFilesToStrings([]string{path}, false); !reflect.DeepEqual(got, []string{"x"}) {
			t.Fatalf("line size %d not accepted: %#v", size, got)
		}
	}
	bad := dictionaryTestFile(t, "discard:salt\n"+strings.Repeat("x", max)+"\n")
	good := dictionaryTestFile(t, "keep:salt\n")
	if got := ReadFilesToStrings([]string{bad}, false); got != nil {
		t.Fatalf("failed file prefix retained: %v", got)
	}
	if got := ReadFilesToStrings([]string{good, bad, good}, false); !reflect.DeepEqual(got, []string{"keep:salt", "keep:salt"}) {
		t.Fatalf("read rollback: %v", got)
	}
	if got := ParseFilesToTargets([]string{bad}); got != nil {
		t.Fatalf("failed targets prefix retained: %v", got)
	}
	if got := ParseFilesToTargets([]string{good, bad, good}); !reflect.DeepEqual(got, []HashSaltTarget{{Hash: "keep", Salt: "salt"}, {Hash: "keep", Salt: "salt"}}) {
		t.Fatalf("target rollback: %v", got)
	}
}

func TestParseFilesToTargetsCompatibility(t *testing.T) {
	old := ConcatSymbol
	t.Cleanup(func() { ConcatSymbol = old })
	for _, separator := range []string{":", "||", "", "盐"} {
		ConcatSymbol = separator
		content := "\n # comment\n#comment\nplain\nhash:salt:pass:ignored\n:missing\nhash::pass\nhash||salt||pass||ignored\n\x00  trimmed:salt  \x00\n\ufeffbom\n中文盐秘密盐pass\ninvalid\xff\n"
		path := dictionaryTestFile(t, content)
		// Reference the original two-stage parsing rules independently of the optimized parser.
		var want []HashSaltTarget
		for _, line := range ReadFilesToStrings([]string{path}, false) {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			sep := separator
			if !strings.Contains(line, sep) {
				sep = ":"
			}
			parts := strings.Split(line, sep)
			if len(parts) == 0 || parts[0] == "" {
				continue
			}
			target := HashSaltTarget{Hash: parts[0]}
			if len(parts) > 1 {
				target.Salt = parts[1]
			}
			want = append(want, target)
		}
		if got := ParseFilesToTargets([]string{path}); !reflect.DeepEqual(got, want) {
			t.Fatalf("separator=%q got=%#v want=%#v", separator, got, want)
		}
		if got := ParseFilesToTargets([]string{path, path}); !reflect.DeepEqual(got, append(append([]HashSaltTarget(nil), want...), want...)) {
			t.Fatalf("separator=%q: multifile order changed", separator)
		}
	}
}

func TestParseHashLineCompatibility(t *testing.T) {
	for _, line := range []string{"", " \t", "hash", ":salt", "hash:", "hash:salt:pass:ignored", "hash||salt||pass||ignored", "中文盐秘密盐明文盐ignored", "\xffabc", "🙂盐x"} {
		for _, separator := range []string{":", "||", "盐", ""} {
			hash, salt, plain, err := ParseHashLine(line, separator)
			if strings.TrimSpace(line) == "" {
				if err == nil {
					t.Fatal("missing empty line error")
				}
				continue
			}
			parts := strings.Split(line, separator)
			want := [3]string{}
			copy(want[:], parts)
			if err != nil || [3]string{hash, salt, plain} != want {
				t.Fatalf("%q/%q got %q %q %q %v want %q", line, separator, hash, salt, plain, err, want)
			}
		}
	}
}
