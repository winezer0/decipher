package cracker

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/schollz/progressbar/v3"
)

func TestDispatchProgressTotals(t *testing.T) {
	for _, count := range []int{0, 1, 100, 10000} {
		for _, width := range []int{9, 40000} {
			for _, saltCount := range []int{0, 4, 1001} {
				t.Run(fmt.Sprintf("%d/%d/%d", count, width, saltCount), func(t *testing.T) {
					plain := strings.Repeat("x", width-3) + "盐"
					plains := make([]string, count)
					for i := range plains {
						plains[i] = plain
					}
					var providers []SaltProvider
					if saltCount > 0 {
						providers = []SaltProvider{NewMemorySaltProvider(batchTestSalts(saltCount), "test")}
					}
					passes := 1 + (saltCount+999)/1000
					bar := progressbar.NewOptions64(1<<40, progressbar.OptionSetWriter(io.Discard), progressbar.OptionThrottle(time.Second))
					tasks := make(chan crackTask, count*passes)
					(&Engine{}).processBatch(context.Background(), tasks, plains, providers, bar)
					close(tasks)
					n := 0
					for range tasks {
						n++
					}
					want := int64(count) * int64(width+1) * int64(passes)
					if n != count*passes || bar.State().CurrentNum != want {
						t.Fatalf("tasks %d progress %d want %d", n, bar.State().CurrentNum, want)
					}
				})
			}
		}
	}
}

func TestDispatchProgressFlushesOnCancellation(t *testing.T) {
	plains := make([]string, 100)
	for i := range plains {
		plains[i] = "中文"
	}
	bar := progressbar.NewOptions64(1<<40, progressbar.OptionSetWriter(io.Discard), progressbar.OptionThrottle(time.Second))
	tasks := make(chan crackTask)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); (&Engine{}).processBatch(ctx, tasks, plains, nil, bar) }()
	for i := 0; i < 7; i++ {
		select {
		case <-tasks:
		case <-time.After(5 * time.Second):
			t.Fatal("missing task")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("producer did not cancel")
	}
	if bar.State().CurrentNum != 49 {
		t.Fatalf("progress %d want 49", bar.State().CurrentNum)
	}
}
