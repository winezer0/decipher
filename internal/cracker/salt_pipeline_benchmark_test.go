package cracker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func saltPipelineFixture(tb testing.TB, kind string, count int) (SaltProvider, []string) {
	tb.Helper()
	values := batchTestSalts(count)
	switch kind {
	case "memory":
		return NewMemorySaltProvider(values, "pipeline"), values
	case "file":
		path := filepath.Join(tb.TempDir(), "salts.txt")
		text := strings.Join(values, "\n")
		if len(values) > 0 {
			text += "\n"
		}
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			tb.Fatal(err)
		}
		return NewFileSaltProvider(path), values
	case "generator":
		charset, length := "0123456789", 1
		switch count {
		case 1:
			charset = "a"
			values = []string{"a"}
		case 4:
			charset = "abcd"
			values = []string{"a", "b", "c", "d"}
		case 1000:
			length = 3
		case 10000:
			length = 4
		default:
			tb.Fatal("unsupported generator size")
		}
		if count >= 1000 {
			for i := range values {
				values[i] = fmt.Sprintf("%0*d", length, i)
			}
		}
		p, err := NewGeneratorSaltProvider(fmt.Sprintf("gen:%d:%s", length, charset))
		if err != nil {
			tb.Fatal(err)
		}
		return p, values
	}
	tb.Fatal("unknown provider")
	return nil, nil
}

func BenchmarkSaltPipeline(b *testing.B) {
	for _, stage := range []string{"source", "multi", "dispatch"} {
		for _, kind := range []string{"memory", "file", "generator"} {
			counts := []int{0, 1, 4, 999, 1000, 1001, 10000}
			if kind == "file" {
				counts = []int{4, 1001, 10000}
			}
			if kind == "generator" {
				counts = []int{1, 4, 1000, 10000}
			}
			for _, count := range counts {
				b.Run(fmt.Sprintf("%s/%s/n%d", stage, kind, count), func(b *testing.B) {
					p, values := saltPipelineFixture(b, kind, count)
					providers := []SaltProvider{p}
					if stage == "multi" {
						p = NewMultiSaltProvider(providers)
					}
					plains := make([]string, 20)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					for i := range plains {
						plains[i] = fmt.Sprintf("plain-%d", i)
					}
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if stage != "dispatch" {
							n := 0
							for salt := range p.GenerateStream(ctx.Done()) {
								if n >= len(values) || salt != values[n] {
									b.Fatal("salt sequence changed")
								}
								n++
							}
							if n != count {
								b.Fatalf("got %d salts want %d", n, count)
							}
							continue
						}
						tasks := make(chan crackTask, 8)
						done := make(chan [2]int, 1)
						go func() {
							n, salts := 0, 0
							for task := range tasks {
								n++
								salts += len(task.salts)
							}
							done <- [2]int{n, salts}
						}()
						(&Engine{}).processBatch(ctx, tasks, plains, providers, nil)
						close(tasks)
						got := <-done
						if got != [2]int{len(plains) * (1 + (count+999)/1000), len(plains) * count} {
							b.Fatalf("incorrect dispatch: %v", got)
						}
					}
				})
			}
		}
	}
}

func BenchmarkSaltPipelineWorkerScale(b *testing.B) {
	for _, kind := range []string{"memory", "file", "generator"} {
		for _, count := range []int{1, 4, 1000, 10000} {
			b.Run(fmt.Sprintf("%s/n%d", kind, count), func(b *testing.B) {
				p, _ := saltPipelineFixture(b, kind, count)
				f := newWorkerFixture(b, workerWorkload{family: "sha256", mode: "dynamic", targets: 3, plains: 3, workers: 4, mixed: true})
				f.salts = []SaltProvider{p}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					f.check(b, f.run())
				}
			})
		}
	}
}
