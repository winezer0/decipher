package cracker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"decipher/internal/algo"
	"decipher/internal/algo/sha"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/winezer0/xutils/logging"
)

type plaintextUnknownReader struct{ io.Reader }

// Size-like methods on custom readers must never be invoked for hints.
func (plaintextUnknownReader) Len() int { panic("unexpected Len call") }

func TestPlaintextProducerReaders(t *testing.T) {
	input := "  中文\r\n\n" + strings.Repeat("long-盐", 20000) + "\nlast"
	for _, kind := range []string{"string", "bytes", "buffer", "unknown", "sized", "underestimated"} {
		t.Run(kind, func(t *testing.T) {
			var reader io.Reader = strings.NewReader(input)
			switch kind {
			case "bytes":
				reader = bytes.NewReader([]byte(input))
			case "buffer":
				reader = bytes.NewBufferString(input)
			case "unknown":
				reader = plaintextUnknownReader{reader}
			case "sized":
				reader = plaintextSizedReader{reader, int64(len(input))}
			case "underestimated":
				reader = plaintextSizedReader{reader, 0}
			}
			tasks := make(chan crackTask, 3)
			(&Engine{}).crackProducer(context.Background(), tasks, reader, nil, nil, time.Now())
			var got []string
			for task := range tasks {
				got = append(got, task.plainLine)
			}
			if !reflect.DeepEqual(got, []string{"中文", strings.Repeat("long-盐", 20000), "last"}) {
				t.Fatal("input changed")
			}
		})
	}
}

func TestPlaintextWorkerBatchBoundary(t *testing.T) {
	for _, workers := range []int{1, 4} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			var input strings.Builder
			var targets []HashSaltTarget
			want := make(map[string]string)
			for i := 0; i < 10001; i++ {
				plain := fmt.Sprintf("candidate-盐-%08d", i)
				fmt.Fprintln(&input, plain)
				if i != 0 && i != 9999 && i != 10000 {
					continue
				}
				for _, salt := range []string{"", "s"} {
					hash := fmt.Sprintf("%x", sha256.Sum256([]byte(salt+"pre-"+plain+"-post")))
					targets = append(targets, HashSaltTarget{Hash: hash})
					want[hash] = "pre-" + plain + "-post"
				}
			}
			e := &Engine{workers: workers, PassPrefix: "pre-", PassSuffix: "-post"}
			got := e.runHashCrackWithDictStream(targets, []algo.Algorithm{&sha.SHA256Algo{}, &sha.SHA256SaltPassAlgo{}}, []SaltProvider{NewMemorySaltProvider([]string{"s"}, "test")}, strings.NewReader(input.String()), time.Now(), nil)
			if len(got) != len(want) {
				t.Fatalf("got %d results want %d", len(got), len(want))
			}
			for _, result := range got {
				plain, ok := want[result.Hash]
				if !ok || result.Plaintext != plain {
					t.Fatalf("unexpected result: %+v", result)
				}
				delete(want, result.Hash)
			}
		})
	}
}

// Retain tasks until scanning finishes to detect strings backed by reused buffers.
func collectPlaintextTasks(t *testing.T, input string, providers []SaltProvider) []crackTask {
	t.Helper()
	tasks := make(chan crackTask, 8)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go (&Engine{}).crackProducer(ctx, tasks, strings.NewReader(input), providers, nil, time.Now())
	var got []crackTask
	for {
		select {
		case task, ok := <-tasks:
			if !ok {
				return got
			}
			got = append(got, task)
		case <-ctx.Done():
			t.Fatal("producer did not finish")
		}
	}
}

func TestPlaintextProducerInputBoundaries(t *testing.T) {
	for _, length := range []int{0, 1, 4095, 4096, 4097, 65535, 65536, 65537, MaxScannerTokenSize - 2} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			plain := strings.Repeat("x", length) + "盐"
			// Keep the final boundary inside the maximum byte limit.
			if len(plain) >= MaxScannerTokenSize {
				plain = strings.Repeat("x", length)
			}
			input := " \r\n\t\n  中文\t\r\n" + plain + "\n\n中文\nend"
			got := collectPlaintextTasks(t, input, nil)
			want := []string{"中文", plain, "中文", "end"}
			if len(got) != len(want) {
				t.Fatalf("got %d tasks, want %d", len(got), len(want))
			}
			for i, task := range got {
				if task.plainLine != want[i] || task.salts != nil {
					t.Fatalf("task %d changed", i)
				}
			}
		})
	}
	for _, length := range []int{MaxScannerTokenSize - 1, MaxScannerTokenSize, MaxScannerTokenSize + 1} {
		t.Run(fmt.Sprintf("limit%d", length), func(t *testing.T) {
			input := "before\n" + strings.Repeat("z", length) + "\nafter"
			got := collectPlaintextTasks(t, input, nil)
			want := []string{"before"}
			if length < MaxScannerTokenSize {
				want = append(want, strings.Repeat("z", length), "after")
			}
			if len(got) != len(want) {
				t.Fatalf("got %d tasks, want %d", len(got), len(want))
			}
			for i := range got {
				if got[i].plainLine != want[i] {
					t.Fatalf("task %d changed", i)
				}
			}
		})
	}
}

func TestPlaintextProducerBatchOrder(t *testing.T) {
	for _, count := range []int{0, 1, 4, 100, 303, 304, 606, 607, 1212, 1213, 2424, 2425, 4848, 4849, 9696, 9697, 9999, 10000, 10001, 20001} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			var input strings.Builder
			plains := make([]string, count)
			for i := range plains {
				plains[i] = fmt.Sprintf("字-%08d", i)
				fmt.Fprintf(&input, " \t%s \r\n\n", plains[i])
			}
			salts := []string{"", "盐", "盐", "x\x00y"}
			got := collectPlaintextTasks(t, input.String(), []SaltProvider{NewMemorySaltProvider(salts, "test")})
			if len(got) != count*2 {
				t.Fatalf("got %d tasks, want %d", len(got), count*2)
			}
			index := 0
			for start := 0; start < count; start += 10000 {
				end := min(start+10000, count)
				for _, dynamic := range []bool{false, true} {
					for _, plain := range plains[start:end] {
						task := got[index]
						index++
						var wantSalts []string
						if dynamic {
							wantSalts = salts
						}
						if task.plainLine != plain || !reflect.DeepEqual(task.salts, wantSalts) {
							t.Fatalf("task %d changed", index-1)
						}
					}
				}
			}
		})
	}
}

func TestPlaintextProducerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tasks := make(chan crackTask)
	done := make(chan struct{})
	go func() {
		defer close(done)
		(&Engine{}).crackProducer(ctx, tasks, strings.NewReader(strings.Repeat("candidate\n", 10001)), nil, nil, time.Now())
	}()
	<-tasks
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled producer remained blocked")
	}
	for range tasks {
	}
}

type plaintextProducerCase struct {
	name  string
	input string
	count int
}

func plaintextProducerCases() []plaintextProducerCase {
	var cases []plaintextProducerCase
	for _, n := range []int{0, 1, 4, 100, 500, 1000, 3000, 5000, 8000, 9999, 10000, 10001} {
		cases = append(cases, plaintextProducerCase{fmt.Sprintf("short%d", n), strings.Repeat("candidate-中文\n", n), n})
	}
	for _, size := range []int{4095, 65535, 131072} {
		cases = append(cases, plaintextProducerCase{fmt.Sprintf("long%d", size), strings.Repeat("x", size) + "\n", 1})
	}
	cases = append(cases, plaintextProducerCase{"mixed100", strings.Repeat("short\n"+strings.Repeat("x", 70000)+"\n", 50), 100})
	return cases
}

func plaintextReader(tb testing.TB, source, input string) func() io.Reader {
	tb.Helper()
	if source == "memory" {
		return func() io.Reader { return strings.NewReader(input) }
	}
	path := filepath.Join(tb.TempDir(), "plain.txt")
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		tb.Fatal(err)
	}
	return func() io.Reader {
		f, err := os.Open(path)
		if err != nil {
			tb.Fatal(err)
		}
		return plaintextSizedReader{Reader: f, size: int64(len(input))}
	}
}

func BenchmarkPlaintextProducer(b *testing.B) {
	if err := logging.InitDefaultLogger(logging.LogConfig{Level: "error", ConsoleFormat: "LCM"}); err != nil {
		b.Fatal(err)
	}
	for _, source := range []string{"memory", "file"} {
		for _, c := range plaintextProducerCases() {
			for _, dynamic := range []bool{false, true} {
				b.Run(fmt.Sprintf("%s/%s/dynamic%t", source, c.name, dynamic), func(b *testing.B) {
					open := plaintextReader(b, source, c.input)
					var providers []SaltProvider
					multiplier := 1
					if dynamic {
						providers = []SaltProvider{NewMemorySaltProvider([]string{"s0", "s1", "s2", "s3"}, "bench")}
						multiplier = 2
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					b.ReportAllocs()
					b.SetBytes(int64(len(c.input)))
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						reader := open()
						tasks := make(chan crackTask, 4)
						done := make(chan int, 1)
						go func() {
							n := 0
							for range tasks {
								n++
							}
							done <- n
						}()
						(&Engine{}).crackProducer(ctx, tasks, reader, providers, nil, time.Time{})
						closePlaintextReader(b, reader)
						if got := <-done; got != c.count*multiplier {
							b.Fatalf("got %d tasks", got)
						}
					}
				})
			}
		}
	}
}

func BenchmarkPlaintextWorker(b *testing.B) {
	if err := logging.InitDefaultLogger(logging.LogConfig{Level: "error", ConsoleFormat: "LCM"}); err != nil {
		b.Fatal(err)
	}
	for _, source := range []string{"memory", "file"} {
		for _, c := range plaintextProducerCases() {
			for _, mode := range []string{"fixed", "dynamic"} {
				b.Run(source+"/"+c.name+"/"+mode, func(b *testing.B) {
					f := newWorkerFixture(b, workerWorkload{family: "sha256", mode: mode, targets: 3, plains: 0, workers: 4, mixed: mode == "dynamic"})
					open := plaintextReader(b, source, c.input)
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						reader := open()
						got := f.engine.runHashCrackWithDictStream(f.targets, f.algorithms, f.salts, reader, time.Now(), nil)
						closePlaintextReader(b, reader)
						f.check(b, got)
					}
				})
			}
		}
	}
}

func closePlaintextReader(tb testing.TB, reader io.Reader) {
	tb.Helper()
	if sized, ok := reader.(plaintextSizedReader); ok {
		reader = sized.Reader
	}
	if closer, ok := reader.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			tb.Fatal(err)
		}
	}
}
