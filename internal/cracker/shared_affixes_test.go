package cracker

import (
	"context"
	"crypto/md5"
	"decipher/internal/algo"
	md5algo "decipher/internal/algo/md5"
	"decipher/internal/algo/types"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func BenchmarkSharedSaltAffixes(b *testing.B) {
	for _, affix := range []bool{false, true} {
		for _, plains := range []int{1, 4, 20} {
			for _, salts := range []int{1, 4, 1000, 10000} {
				b.Run(fmt.Sprintf("affix%t/p%d/s%d", affix, plains, salts), func(b *testing.B) {
					f := newWorkerFixture(b, workerWorkload{family: "sha256", mode: "dynamic", targets: 3, plains: plains, workers: 4, mixed: true, affix: affix})
					f.salts = []SaltProvider{NewMemorySaltProvider(batchTestSalts(salts), "bench")}
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						f.check(b, f.run())
					}
				})
			}
		}
	}
}

func TestSharedAffixesStayImmutableAcrossBatches(t *testing.T) {
	e := &Engine{SaltPrefix: "s:", SaltSuffix: ":end"}
	plains := make([]string, 20)
	for i := range plains {
		plains[i] = fmt.Sprint(i)
	}
	salts := batchTestSalts(1001)
	tasks := make(chan crackTask, 60)
	e.processBatch(context.Background(), tasks, plains, []SaltProvider{NewMemorySaltProvider(salts, "test")}, nil, crackDispatchOptions{shareSaltAffixes: true})
	close(tasks)
	var first, last *preparedSaltBatch
	n := 0
	for task := range tasks {
		if task.salts == nil {
			continue
		}
		if task.affixedSalts == nil {
			t.Fatal("missing prepared salts")
		}
		start := 0
		if n >= 20 {
			start = 1000
		}
		for i, salt := range task.salts {
			if salt != salts[start+i] || task.affixedSalts.values[i] != "s:"+salt+":end" {
				t.Fatal("batch overwritten")
			}
		}
		if n == 0 {
			first = task.affixedSalts
		}
		if n == 20 {
			last = task.affixedSalts
		}
		if n < 20 && first != task.affixedSalts || n >= 20 && last != task.affixedSalts {
			t.Fatal("batch not shared")
		}
		n++
	}
	if n != 40 || first == last {
		t.Fatal("batch storage reused")
	}
}

func TestCustomAlgorithmsRetainTaskLocalSaltAffixes(t *testing.T) {
	e := &Engine{workers: 1, SaltPrefix: "before:"}
	calls := 0
	a := &workerProbeAlgo{label: "custom", salted: true, recover: func(_, salt, _ string) (string, error) {
		prefix := "after:"
		if calls < 2 {
			prefix = "before:"
		}
		if !strings.HasPrefix(salt, prefix) {
			t.Errorf("task affix changed: %q", salt)
		}
		calls++
		e.SaltPrefix = "after:"
		return "", types.ErrVerificationFailed
	}}
	e.runHashCrackWithDictStream([]HashSaltTarget{{Hash: "custom"}}, []algo.Algorithm{a}, []SaltProvider{NewMemorySaltProvider([]string{"a", "b"}, "test")}, strings.NewReader(strings.Repeat("plain\n", 20)), time.Now(), nil)
	if calls != 40 {
		t.Fatalf("got %d calls", calls)
	}
}

func TestSharedAffixedSaltBatchesCrackCorrectly(t *testing.T) {
	salts := batchTestSalts(2001)
	var input strings.Builder
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&input, "plain-%02d\n", i)
	}
	e := &Engine{workers: 4, PassPrefix: "p:", SaltPrefix: "s:", SaltSuffix: ":end"}
	var targets []HashSaltTarget
	want := map[string]string{}
	for _, i := range []int{0, 999, 1000, 1999, 2000} {
		hash := fmt.Sprintf("%x", md5.Sum([]byte("s:"+salts[i]+":endp:plain-19")))
		targets = append(targets, HashSaltTarget{Hash: hash})
		want[hash] = salts[i]
	}
	got := e.runHashCrackWithDictStream(targets, []algo.Algorithm{&md5algo.MD5SaltPassAlgo{}}, []SaltProvider{NewMemorySaltProvider(salts, "test")}, strings.NewReader(input.String()), time.Now(), nil)
	if len(got) != len(want) {
		t.Fatalf("got %d results", len(got))
	}
	for _, r := range got {
		salt, ok := want[r.Hash]
		if !ok || r.Salt != salt || r.Plaintext != "p:plain-19" {
			t.Fatalf("incorrect result: %+v", r)
		}
		delete(want, r.Hash)
	}
}

// Empty-only salts and short plaintext batches remain valid input as well.
func TestAffixedSaltProducerInputs(t *testing.T) {
	for _, count := range []int{1, 4, 20} {
		plains := make([]string, count)
		for i := range plains {
			plains[i] = fmt.Sprint(i)
		}
		tasks := make(chan crackTask, count*2)
		(&Engine{SaltPrefix: "s:"}).processBatch(context.Background(), tasks, plains, []SaltProvider{NewMemorySaltProvider([]string{"", "a", "a"}, "test")}, nil)
		close(tasks)
		n := 0
		for task := range tasks {
			if len(task.salts) > 0 {
				if strings.Join(task.salts, ",") != ",a,a" {
					t.Fatal("raw salts changed")
				}
				n++
			}
		}
		if n != count {
			t.Fatal("missing dynamic tasks")
		}
	}
}

func TestPrepareSaltAffixesThresholds(t *testing.T) {
	tests := []struct {
		name      string
		prefix    string
		suffix    string
		plains    int
		salts     []string
		enabled   bool
		wantBatch bool
	}{
		{name: "disabled", prefix: "p:", plains: 20, salts: []string{"a"}, wantBatch: false},
		{name: "below plaintext threshold", prefix: "p:", plains: 15, salts: []string{"a"}, enabled: true, wantBatch: false},
		{name: "no affix", plains: 20, salts: []string{"a"}, enabled: true, wantBatch: false},
		{name: "sparse salts", prefix: "p:", plains: 20, salts: []string{"", "", "", "", "a"}, enabled: true, wantBatch: false},
		{name: "one quarter nonempty", suffix: ":s", plains: 16, salts: []string{"", "a", "", "b"}, enabled: true, wantBatch: true},
		{name: "empty salts", prefix: "p:", plains: 20, salts: []string{"", ""}, enabled: true, wantBatch: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Engine{SaltPrefix: tt.prefix, SaltSuffix: tt.suffix}
			original := append([]string(nil), tt.salts...)
			got := e.prepareSaltAffixes(tt.salts, tt.plains, tt.enabled)
			if (got != nil) != tt.wantBatch {
				t.Fatalf("batch allocated=%t want %t", got != nil, tt.wantBatch)
			}
			if got != nil {
				if len(got.values) != len(tt.salts) {
					t.Fatalf("got %d affixed salts, want %d", len(got.values), len(tt.salts))
				}
				for i, salt := range tt.salts {
					if want := tt.prefix + salt + tt.suffix; got.values[i] != want {
						t.Errorf("salt %d = %q want %q", i, got.values[i], want)
					}
				}
			}
			if !reflect.DeepEqual(tt.salts, original) {
				t.Fatal("input salts were modified")
			}
		})
	}
}
