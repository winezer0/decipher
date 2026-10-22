package cracker

import (
	"context"
	"decipher/internal/algo"
	"decipher/internal/algo/md5"
	"decipher/internal/algo/types"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type workerProbeAlgo struct {
	md5.MD5Algo
	label   string
	salted  bool
	recover func(string, string, string) (string, error)
}

func TestCrackWorkerSaltScratchDoesNotModifySharedBatch(t *testing.T) {
	engine := &Engine{workers: 1, PassPrefix: "p:", SaltPrefix: "s:", SaltSuffix: ":end"}
	var got []string
	alg := &workerProbeAlgo{label: "probe", salted: true, recover: func(hash, salt, plain string) (string, error) {
		got = append(got, hash+"/"+salt+"/"+plain)
		return "", types.ErrVerificationFailed
	}}
	strategies := engine.prepareCrackStrategies([]HashSaltTarget{{Hash: "A"}, {Hash: "B"}}, []algo.Algorithm{alg})
	shared := []string{"a", "b", "c"}
	tasks := []crackTask{{plainLine: "one", salts: shared}, {plainLine: "two", salts: []string{"d"}}, {plainLine: "three", salts: shared}, {plainLine: "", salts: shared}, {plainLine: "four", salts: []string{""}}}
	jobs := make(chan crackTask, len(tasks))
	for _, task := range tasks {
		jobs <- task
	}
	close(jobs)
	engine.crackWorker(context.Background(), jobs, make(chan CrackerResult), strategies)
	var want []string
	for _, task := range tasks {
		if task.plainLine == "" {
			continue
		}
		for _, hash := range []string{"A", "B"} {
			for _, salt := range task.salts {
				want = append(want, hash+"/s:"+salt+":end/p:"+task.plainLine)
			}
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scratch values changed: got %v want %v", got, want)
	}
	if !reflect.DeepEqual(shared, []string{"a", "b", "c"}) {
		t.Fatalf("shared salt batch mutated: %v", shared)
	}
}

func TestCrackWorkerCancellation(t *testing.T) {
	for _, mode := range []string{"idle", "miss", "blocked-result"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			engine := &Engine{workers: 1}
			var calls atomic.Int32
			var once sync.Once
			attempted := make(chan struct{})
			alg := &workerProbeAlgo{label: "probe", salted: true, recover: func(hash, salt, plain string) (string, error) {
				calls.Add(1)
				once.Do(func() { close(attempted) })
				if mode == "blocked-result" {
					return plain, nil
				}
				cancel()
				return "", types.ErrVerificationFailed
			}}
			strategies := engine.prepareCrackStrategies([]HashSaltTarget{{Hash: "A"}}, []algo.Algorithm{alg, alg})
			jobs := make(chan crackTask, 1)
			if mode != "idle" {
				jobs <- crackTask{plainLine: "candidate", salts: []string{"a", "b", "c"}}
			}
			done := make(chan struct{})
			go func() { defer close(done); engine.crackWorker(ctx, jobs, make(chan CrackerResult), strategies) }()
			if mode == "idle" {
				cancel()
			} else {
				select {
				case <-attempted:
				case <-time.After(5 * time.Second):
					t.Fatal("no algorithm attempt")
				}
				cancel()
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("worker failed to cancel")
			}
			if mode != "idle" && calls.Load() != 1 {
				t.Fatalf("continued after cancel: %d calls", calls.Load())
			}
		})
	}
}

func (a *workerProbeAlgo) Name() string              { return a.label }
func (a *workerProbeAlgo) NeedSalt() bool            { return a.salted }
func (a *workerProbeAlgo) Identify(hash string) bool { return hash != "reject" }
func (a *workerProbeAlgo) Recover(hash, salt, plain string) (string, error) {
	return a.recover(hash, salt, plain)
}

func TestCrackWorkerPreservesAttemptOrderAndFields(t *testing.T) {
	engine := &Engine{workers: 1, PassPrefix: "p(", PassSuffix: ")", SaltPrefix: "s(", SaltSuffix: ")"}
	var calls []string
	probe := func(label string, salted bool) algo.Algorithm {
		return &workerProbeAlgo{label: label, salted: salted, recover: func(hash, salt, plain string) (string, error) {
			calls = append(calls, fmt.Sprintf("%s %s %s %s", label, hash, salt, plain))
			if label == "salted" && ((hash == "A" && salt == "s(S)") || (hash == "B" && salt == "s(dynamic)")) {
				return "verified:" + plain, nil
			}
			if label == "last" {
				return "verified:" + plain, nil
			}
			return "", types.ErrVerificationFailed
		}}
	}
	algorithms := []algo.Algorithm{probe("first", false), probe("salted", true), probe("last", false)}
	targets := []HashSaltTarget{{Hash: "A", Salt: "S"}, {Hash: "A", Salt: "T"}, {Hash: "B"}, {Hash: "reject"}}
	got := engine.runHashCrackWithDictStream(targets, algorithms, []SaltProvider{NewMemorySaltProvider([]string{"wrong", "dynamic"}, "test")}, strings.NewReader("candidate\n"), time.Now(), nil)
	want := []CrackerResult{
		{Hash: "A", Salt: "S", Algorithm: "salted", AlgoType: string(types.AlgoIsStatic), Plaintext: "verified:p(candidate)"},
		{Hash: "A", Salt: "T", Algorithm: "last", AlgoType: string(types.AlgoIsStatic), Plaintext: "verified:p(candidate)"},
		{Hash: "B", Algorithm: "last", AlgoType: string(types.AlgoIsStatic), Plaintext: "verified:p(candidate)"},
		{Hash: "B", Salt: "dynamic", Algorithm: "salted", AlgoType: string(types.AlgoIsStatic), Plaintext: "verified:p(candidate)"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
	wantCalls := []string{
		"first A s(S) p(candidate)", "salted A s(S) p(candidate)",
		"first A s(T) p(candidate)", "salted A s(T) p(candidate)", "last A s(T) p(candidate)",
		"first B s() p(candidate)", "last B s() p(candidate)",
		"salted B s(wrong) p(candidate)", "salted B s(dynamic) p(candidate)",
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("attempt order changed: %#v", calls)
	}
}

func TestCrackWorkerPipelineWorkloads(t *testing.T) {
	for _, w := range workerWorkloads {
		t.Run(w.name, func(t *testing.T) { fixture := newWorkerFixture(t, w); fixture.check(t, fixture.run()) })
	}
}

func TestCrackWorkerAllFailuresAndEmptyInputs(t *testing.T) {
	engine := &Engine{workers: 2}
	alg := &workerProbeAlgo{label: "fail", recover: func(string, string, string) (string, error) { return "", types.ErrVerificationFailed }}
	for _, input := range []string{"", "\n \t\n", "candidate\n"} {
		for _, targets := range [][]HashSaltTarget{nil, {{Hash: "hash"}}, {{Hash: "reject"}}} {
			got := engine.runHashCrackWithDictStream(targets, []algo.Algorithm{alg}, nil, strings.NewReader(input), time.Now(), nil)
			if len(got) != 0 {
				t.Fatalf("unexpected results: %v", got)
			}
		}
	}
}
