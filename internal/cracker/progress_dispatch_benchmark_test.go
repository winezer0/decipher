package cracker

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/winezer0/xutils/logging"
)

func BenchmarkProgressDispatch(b *testing.B) {
	for _, dynamic := range []bool{false, true} {
		b.Run(fmt.Sprint(dynamic), func(b *testing.B) {
			plains := make([]string, 10000)
			for i := range plains {
				plains[i] = "candidate"
			}
			var providers []SaltProvider
			passes := 1
			if dynamic {
				providers = []SaltProvider{NewMemorySaltProvider([]string{"a", "b", "c", "d"}, "bench")}
				passes = 2
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				bar := progressbar.NewOptions64(1<<40, progressbar.OptionSetWriter(io.Discard), progressbar.OptionThrottle(time.Second))
				tasks := make(chan crackTask, 4)
				done := make(chan int, 1)
				go func() {
					n := 0
					for range tasks {
						n++
					}
					done <- n
				}()
				(&Engine{}).processBatch(context.Background(), tasks, plains, providers, bar)
				close(tasks)
				if got := <-done; got != len(plains)*passes {
					b.Fatal("task count changed")
				}
				if bar.State().CurrentNum != int64(len(plains)*10*passes) {
					b.Fatal("progress changed")
				}
			}
		})
	}
}

func BenchmarkLongDictionaryProgress(b *testing.B) {
	if err := logging.InitDefaultLogger(logging.LogConfig{Level: "error", ConsoleFormat: "LCM"}); err != nil {
		b.Fatal(err)
	}
	for _, workers := range []int{1, 4} {
		for _, plains := range []int{10000, 100000} {
			b.Run(fmt.Sprintf("w%d/p%d", workers, plains), func(b *testing.B) {
				path := filepath.Join(b.TempDir(), "dict.txt")
				if err := os.WriteFile(path, []byte(strings.Repeat("candidate\n", plains)), 0600); err != nil {
					b.Fatal(err)
				}
				f := newWorkerFixture(b, workerWorkload{family: "sha256", mode: "fixed", targets: 3, workers: workers})
				restore := discardDictionaryConsole(b)
				defer restore()
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					f.check(b, f.engine.RunHashCrack(f.targets, []string{path}, nil, f.algorithms))
				}
			})
		}
	}
}
