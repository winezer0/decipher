package cracker

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/schollz/progressbar/v3"
)

type dispatchSaltProbe struct{ calls, generated atomic.Int32 }

func (*dispatchSaltProbe) Name() string { return "probe" }
func (*dispatchSaltProbe) Count() int64 { panic("unexpected Count call") }
func (p *dispatchSaltProbe) GenerateStream(done <-chan struct{}) <-chan string {
	p.calls.Add(1)
	out := make(chan string)
	go func() {
		defer close(out)
		for i := 0; i < 1001; i++ {
			select {
			case <-done:
				return
			case out <- fmt.Sprint(i):
				p.generated.Add(1)
			}
		}
	}()
	return out
}

func TestUnusedPassesKeepSourcesProgressAndTaskOrder(t *testing.T) {
	plains := []string{"one", "中文", "one"}
	var all []crackTask
	for _, options := range []crackDispatchOptions{{}, {skipFixed: true}, {skipDynamic: true}, {skipFixed: true, skipDynamic: true}} {
		tasks := make(chan crackTask, 9)
		probe := &dispatchSaltProbe{}
		bar := progressbar.NewOptions64(1<<40, progressbar.OptionSetWriter(io.Discard), progressbar.OptionThrottle(time.Hour))
		(&Engine{}).processBatch(context.Background(), tasks, plains, []SaltProvider{probe}, bar, options)
		close(tasks)
		var got []crackTask
		for task := range tasks {
			got = append(got, task)
		}
		if probe.calls.Load() != 1 || probe.generated.Load() != 1001 {
			t.Fatal("source consumption changed")
		}
		wantProgress := int64(0)
		for _, p := range plains {
			wantProgress += int64(len(p)+1) * 3
		}
		if bar.State().CurrentNum != wantProgress {
			t.Fatalf("progress=%d want %d", bar.State().CurrentNum, wantProgress)
		}
		if !options.skipFixed && !options.skipDynamic {
			all = got
			continue
		}
		var want []crackTask
		for _, task := range all {
			if task.salts == nil && !options.skipFixed || task.salts != nil && !options.skipDynamic {
				want = append(want, task)
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatal("selected task order changed")
		}
	}
}

func TestSkippedPassStillCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		(&Engine{}).processBatch(ctx, make(chan crackTask), []string{"plain"}, nil, nil, crackDispatchOptions{skipFixed: true, skipDynamic: true})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("skipped pass did not cancel")
	}
}
