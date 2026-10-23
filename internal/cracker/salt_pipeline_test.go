package cracker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

type saltPipelineProbe struct {
	MemorySaltProvider
	values     []string
	calls      *int
	countCalls *int
	reported   int64
}

func (p *saltPipelineProbe) Count() int64 { *p.countCalls++; return p.reported }
func (p *saltPipelineProbe) GenerateStream(done <-chan struct{}) <-chan string {
	*p.calls++
	out := make(chan string)
	go func() {
		defer close(out)
		for _, s := range p.values {
			select {
			case <-done:
				return
			case out <- s:
			}
		}
	}()
	return out
}

func TestSaltPipelinePreservesSources(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "salts.txt")
	if err := os.WriteFile(path, []byte(" a \r\n\n b\n a\n"), 0600); err != nil {
		t.Fatal(err)
	}
	gen, err := NewGeneratorSaltProvider("gen:0:1:aa")
	if err != nil {
		t.Fatal(err)
	}
	unicodeGen, err := NewGeneratorSaltProvider("gen:1:盐a")
	if err != nil {
		t.Fatal(err)
	}
	for _, reported := range []int64{-1, 0, 1, 1 << 62} {
		calls, counts := 0, 0
		wrapped := &saltPipelineProbe{values: []string{"wrapped", "", "wrapped"}, calls: &calls, countCalls: &counts, reported: reported}
		p := NewMultiSaltProvider([]SaltProvider{
			NewMemorySaltProvider([]string{"", " a ", "\x00", "a"}, "memory"),
			NewMultiSaltProvider([]SaltProvider{NewFileSaltProvider(path), gen, unicodeGen, wrapped}),
		})
		var got []string
		for s := range p.GenerateStream(nil) {
			got = append(got, s)
		}
		want := []string{"", " a ", "\x00", "a", "a", "b", "a", "", "a", "a", "盐", "a", "wrapped", "", "wrapped"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("sequence changed: %q", got)
		}
		if calls != 1 || counts != 0 {
			t.Fatalf("wrapped provider bypassed or Count invoked: %d/%d", calls, counts)
		}
	}
}

func TestSaltPipelineMultiplePlainBatches(t *testing.T) {
	calls, counts := 0, 0
	p := &saltPipelineProbe{values: []string{"x", "", "x", "y"}, calls: &calls, countCalls: &counts, reported: 0}
	var input strings.Builder
	for i := 0; i < 10001; i++ {
		fmt.Fprintf(&input, "plain-%d\n", i)
	}
	tasks := make(chan crackTask, 20002)
	(&Engine{}).crackProducer(context.Background(), tasks, strings.NewReader(input.String()), []SaltProvider{p}, nil, time.Now())
	index := 0
	for task := range tasks {
		var plainIndex int
		switch {
		case index < 10000:
			plainIndex = index
		case index < 20000:
			plainIndex = index - 10000
			if !reflect.DeepEqual(task.salts, p.values) {
				t.Fatal("first batch salts changed")
			}
		case index == 20000:
			plainIndex = 10000
		case index == 20001:
			plainIndex = 10000
			if !reflect.DeepEqual(task.salts, p.values) {
				t.Fatal("second batch salts changed")
			}
		default:
			t.Fatal("extra task")
		}
		if task.plainLine != fmt.Sprintf("plain-%d", plainIndex) {
			t.Fatalf("task order changed at %d", index)
		}
		if (index < 10000 || index == 20000) && task.salts != nil {
			t.Fatal("fixed task changed")
		}
		index++
	}
	if index != 20002 || calls != 2 || counts != 0 {
		t.Fatalf("tasks/calls/Count: %d/%d/%d", index, calls, counts)
	}
}

func TestSaltPipelineNestedMemory(t *testing.T) {
	for _, count := range []int{0, 1, 4, 999, 1000, 1001, 10000} {
		values := batchTestSalts(count)
		mid := count / 2
		p := NewMultiSaltProvider([]SaltProvider{
			NewMemorySaltProvider(nil, "empty"),
			NewMultiSaltProvider([]SaltProvider{NewMemorySaltProvider(values[:mid], "first"), NewMemorySaltProvider(values[mid:], "last")}),
		})
		index := 0
		for salt := range p.GenerateStream(nil) {
			if index >= len(values) || salt != values[index] {
				t.Fatalf("nested source changed at %d", index)
			}
			index++
		}
		if index != count {
			t.Fatalf("got %d salts want %d", index, count)
		}
	}
}

func saltPipelineWait(t *testing.T, condition func() bool) bool {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if condition() {
			return true
		}
		select {
		case <-deadline.C:
			return false
		case <-tick.C:
		}
	}
}

func saltPipelineStreamState(marker string) (running, blocked bool) {
	buf := make([]byte, 256*1024)
	stack := string(buf[:runtime.Stack(buf, true)])
	for _, g := range strings.Split(stack, "\n\n") {
		if strings.Contains(g, marker) {
			running = true
			blocked = blocked || strings.Contains(strings.SplitN(g, "\n", 2)[0], "[chan send]") || strings.Contains(strings.SplitN(g, "\n", 2)[0], "[select]")
		}
	}
	return
}

// 隔离进程避免其他测试的同类流影响协程退出检查，不通过排空通道来掩盖阻塞。
func TestSaltPipelineCancellation(t *testing.T) {
	if kind := os.Getenv("DECIPHER_SALT_PIPELINE_CANCEL"); kind != "" {
		marker := "decipher/internal/cracker.(*" + map[string]string{"memory": "Memory", "file": "File", "generator": "Generator", "multi": "Multi"}[kind] + "SaltProvider).GenerateStream"
		newProvider := func() SaltProvider {
			source := kind
			if source == "multi" {
				source = "memory"
			}
			p, _ := saltPipelineFixture(t, source, 10000)
			if kind == "multi" {
				return NewMultiSaltProvider([]SaltProvider{p})
			}
			return p
		}
		for _, consume := range []int{0, 8} {
			p := newProvider()
			ctx, cancel := context.WithCancel(context.Background())
			ch := p.GenerateStream(ctx.Done())
			// 失败时仍排空以释放旧实现可能阻塞的发送。
			cleanup := func() {
				cancel()
				for range ch {
				}
			}
			for i := 0; i < consume; i++ {
				select {
				case <-ch:
				case <-time.After(2 * time.Second):
					cleanup()
					t.Fatal("missing salts")
				}
			}
			if !saltPipelineWait(t, func() bool { _, blocked := saltPipelineStreamState(marker); return len(ch) == cap(ch) && blocked }) {
				cleanup()
				t.Fatal("producer did not reach a full blocked buffer")
			}
			cancel()
			if !saltPipelineWait(t, func() bool {
				running, _ := saltPipelineStreamState(marker)
				if kind == "multi" {
					child, _ := saltPipelineStreamState("decipher/internal/cracker.(*MemorySaltProvider).GenerateStream")
					running = running || child
				}
				return !running
			}) {
				cleanup()
				t.Fatal("cancelled producer remains blocked without a consumer")
			}
			for range ch {
			}
			if file, ok := p.(*FileSaltProvider); ok {
				if err := os.Rename(file.filePath, file.filePath+".closed"); err != nil {
					t.Fatalf("cancelled file source still holds its file: %v", err)
				}
			}
		}
		p := newProvider()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		ch := p.GenerateStream(ctx.Done())
		finished := make(chan struct{})
		go func() {
			for range ch {
			}
			close(finished)
		}()
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
			t.Fatal("pre-cancelled stream did not close")
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"memory", "file", "generator", "multi"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestSaltPipelineCancellation$")
			cmd.Env = append(os.Environ(), "DECIPHER_SALT_PIPELINE_CANCEL="+kind)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("child: %v %s", err, out)
			}
		})
	}
}
