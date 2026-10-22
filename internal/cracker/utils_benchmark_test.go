package cracker

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type dictionaryWorkload struct {
	name                               string
	files, lines, lineBytes, tailBytes int
	targets                            bool
}

var dictionaryWorkloads = []dictionaryWorkload{
	{name: "read_small", files: 1, lines: 64, lineBytes: 64},
	{name: "read_short", files: 1, lines: 100000, lineBytes: 64},
	{name: "read_long", files: 1, lines: 16, lineBytes: 256 * 1024},
	{name: "read_multifile", files: 32, lines: 8, lineBytes: 64},
	{name: "targets_small", files: 1, lines: 64, targets: true},
	{name: "targets_short", files: 1, lines: 100000, targets: true},
	{name: "targets_tail", files: 1, lines: 2000, tailBytes: 8192, targets: true},
	{name: "targets_multifile", files: 32, lines: 8, targets: true},
}

func dictionaryFixture(t testing.TB, w dictionaryWorkload) []string {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	for f := 0; f < w.files; f++ {
		path := filepath.Join(dir, fmt.Sprintf("input-%d.txt", f))
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		writer := bufio.NewWriter(file)
		for i := 0; i < w.lines; i++ {
			index := f*w.lines + i
			var line string
			if w.targets {
				line = fmt.Sprintf("%032x:salt-%08d", index, index)
				if w.tailBytes > 0 {
					line += ":" + strings.Repeat("x", w.tailBytes)
				}
			} else {
				line = fmt.Sprintf("plain-%08d-", index)
				line += strings.Repeat("x", w.lineBytes-len(line))
			}
			if _, err := writer.WriteString(line + "\n"); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Flush(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	return paths
}

type dictionaryOutput struct {
	lines   []string
	targets []HashSaltTarget
}

func runDictionaryWorkload(paths []string, w dictionaryWorkload) dictionaryOutput {
	if w.targets {
		return dictionaryOutput{targets: ParseFilesToTargets(paths)}
	}
	return dictionaryOutput{lines: ReadFilesToStrings(paths, false)}
}

func checkDictionaryOutput(t testing.TB, output dictionaryOutput, w dictionaryWorkload) {
	t.Helper()
	want := w.files * w.lines
	if len(output.lines)+len(output.targets) != want {
		t.Fatalf("%s: wrong record count", w.name)
	}
	if w.targets {
		for _, index := range []int{0, want - 1} {
			if output.targets[index].Hash != fmt.Sprintf("%032x", index) || output.targets[index].Salt != fmt.Sprintf("salt-%08d", index) {
				t.Fatalf("%s: wrong target at %d", w.name, index)
			}
		}
	} else if !strings.HasPrefix(output.lines[0], "plain-00000000-") || len(output.lines[want-1]) != w.lineBytes {
		t.Fatalf("%s: wrong line contents", w.name)
	}
}

func BenchmarkDictionaryInput(b *testing.B) {
	for _, w := range dictionaryWorkloads {
		b.Run(w.name, func(b *testing.B) {
			paths := dictionaryFixture(b, w)
			b.ReportAllocs()
			b.ResetTimer()
			var output dictionaryOutput
			for i := 0; i < b.N; i++ {
				output = runDictionaryWorkload(paths, w)
				if len(output.lines)+len(output.targets) != w.files*w.lines {
					b.Fatal("wrong record count")
				}
			}
			b.StopTimer()
			checkDictionaryOutput(b, output, w)
			runtime.KeepAlive(output)
		})
	}
}
