package cracker

import (
	"crypto/sha256"
	"decipher/internal/algo"
	"decipher/internal/algo/sha"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	logging "github.com/winezer0/zaplogs"
)

func discardDictionaryConsole(tb testing.TB) func() {
	tb.Helper()
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0600)
	if err != nil {
		tb.Fatal(err)
	}
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = null, null
	return func() { os.Stdout, os.Stderr = stdout, stderr; null.Close() }
}

func BenchmarkMultiDictionaryPreparation(b *testing.B) {
	if err := logging.InitDefaultLogger(logging.LogConfig{Level: "error", ConsoleFormat: "LCM"}); err != nil {
		b.Fatal(err)
	}
	for _, count := range []int{1, 8} {
		for _, targets := range []int{1, 1000, 100000} {
			b.Run(fmt.Sprintf("d%d/t%d", count, targets), func(b *testing.B) {
				paths := make([]string, count)
				for i := range paths {
					paths[i] = filepath.Join(b.TempDir(), "dict.txt")
					if err := os.WriteFile(paths[i], []byte("candidate\n"), 0600); err != nil {
						b.Fatal(err)
					}
				}
				f := newWorkerFixture(b, workerWorkload{family: "sha256", mode: "fixed", targets: targets, workers: 4, mixed: true})
				restore := discardDictionaryConsole(b)
				defer restore()
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					got := f.engine.RunHashCrack(f.targets, paths, nil, f.algorithms)
					f.check(b, got)
				}
			})
		}
	}
}

func TestMultiDictionaryKeepsDuplicateResultsAndCustomIdentify(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	paths = append(paths, filepath.Join(dir, "missing"))
	for i := 0; i < 2; i++ {
		p := filepath.Join(dir, fmt.Sprint(i))
		if err := os.WriteFile(p, []byte("candidate\n"), 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	restore := discardDictionaryConsole(t)
	defer restore()
	e := &Engine{workers: 1}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte("candidate")))
	got := e.RunHashCrack([]HashSaltTarget{{Hash: hash}}, paths, nil, []algo.Algorithm{&sha.SHA256Algo{}})
	if len(got) != 2 || got[0] != got[1] || got[0].Plaintext != "candidate" || got[0].Hash != hash {
		t.Fatal("dictionary results changed")
	}
	var calls []string
	wrapper := &identifyPreparedSHA256{calls: &calls}
	got = e.RunHashCrack([]HashSaltTarget{{Hash: hash}}, paths, nil, []algo.Algorithm{wrapper})
	if len(got) != 0 || len(calls) != 2 {
		t.Fatalf("Identify calls=%d results=%d", len(calls), len(got))
	}
}

func TestMultiDictionaryStrategiesDoNotPersistAcrossCommands(t *testing.T) {
	var paths []string
	for i := 0; i < 2; i++ {
		path := filepath.Join(t.TempDir(), "plain.txt")
		if err := os.WriteFile(path, []byte("candidate\n"), 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	restore := discardDictionaryConsole(t)
	defer restore()
	e := &Engine{workers: 4}
	for _, prefix := range []string{"first:", "second:"} {
		e.SaltPrefix = prefix
		e.PassPrefix = prefix
		plain := prefix + "candidate"
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(prefix+"raw"+plain)))
		got := e.RunHashCrack([]HashSaltTarget{{Hash: hash, Salt: "raw"}}, paths, nil, []algo.Algorithm{&sha.SHA256SaltPassAlgo{}})
		if len(got) != 2 {
			t.Fatalf("got %d results", len(got))
		}
		for _, r := range got {
			if r.Hash != hash || r.Plaintext != plain || r.Salt != "raw" {
				t.Fatal("state retained between commands")
			}
		}
	}
}
