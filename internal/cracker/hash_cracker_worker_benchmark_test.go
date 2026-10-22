package cracker

import (
	"decipher/internal/algo"
	"decipher/internal/algo/md5"
	"fmt"
	"strings"
	"testing"
	"time"
)

type workerWorkload struct {
	name, mode, hit          string
	targets, plains, workers int
	mixed, affix             bool
}

var workerWorkloads = []workerWorkload{
	{name: "fixed_1_w1", mode: "fixed", targets: 1, plains: 1000, workers: 1},
	{name: "fixed_100_w4", mode: "fixed", targets: 100, plains: 100, workers: 4},
	{name: "fixed_1000_mixed_w4", mode: "fixed", targets: 1000, plains: 10, workers: 4, mixed: true},
	{name: "mixed_100_w1", mode: "mixed", targets: 100, plains: 20, workers: 1, mixed: true},
	{name: "mixed_100_affix_w4", mode: "mixed", targets: 100, plains: 20, workers: 4, mixed: true, affix: true},
	{name: "dynamic_100_w4", mode: "dynamic", targets: 100, plains: 20, workers: 4, mixed: true},
	{name: "hit_early_w4", mode: "fixed", targets: 100, plains: 20, workers: 4, mixed: true, hit: "early"},
	{name: "hit_late_affix_w4", mode: "fixed", targets: 100, plains: 20, workers: 4, mixed: true, affix: true, hit: "late"},
}

type workerFixture struct {
	engine     *Engine
	targets    []HashSaltTarget
	algorithms []algo.Algorithm
	salts      []SaltProvider
	input      string
	want       []CrackerResult
}

func newWorkerFixture(t testing.TB, w workerWorkload) workerFixture {
	t.Helper()
	f := workerFixture{engine: &Engine{workers: w.workers}, algorithms: []algo.Algorithm{&md5.MD5Algo{}}}
	if w.affix {
		f.engine.PassPrefix = "pre-"
		f.engine.PassSuffix = "-post"
		f.engine.SaltPrefix = "s-pre-"
		f.engine.SaltSuffix = "-s-post"
	}
	if w.mixed {
		f.algorithms = append(f.algorithms, &md5.MD5SaltPassAlgo{}, &md5.MD5PassSaltAlgo{})
	}
	if w.mode != "fixed" {
		f.salts = []SaltProvider{NewMemorySaltProvider([]string{"s0", "s1", "s2", "s3"}, "worker-benchmark")}
	}
	var input strings.Builder
	for i := 0; i < w.plains; i++ {
		fmt.Fprintf(&input, "candidate-%08d\n", i)
	}
	f.input = input.String()
	for i := 0; i < w.targets; i++ {
		target := HashSaltTarget{Hash: fmt.Sprintf("%032x", i+1)}
		if w.mode == "mixed" && i%2 == 0 {
			target.Salt = fmt.Sprintf("s%d", i%4)
		}
		f.targets = append(f.targets, target)
	}
	if w.hit != "" {
		index := 0
		if w.hit == "late" {
			index = w.plains - 1
		}
		plain := f.engine.AffixPasswd(fmt.Sprintf("candidate-%08d", index))
		hash, err := f.algorithms[0].Seal(plain, f.engine.AffixSalt(""))
		if err != nil {
			t.Fatal(err)
		}
		f.targets[0].Hash = hash
		f.want = []CrackerResult{{Hash: hash, Plaintext: plain, Algorithm: f.algorithms[0].Name(), AlgoType: string(f.algorithms[0].GetAlgoType())}}
	}
	return f
}

func (f workerFixture) run() []CrackerResult {
	return f.engine.runHashCrackWithDictStream(f.targets, f.algorithms, f.salts, strings.NewReader(f.input), time.Now(), nil)
}

func (f workerFixture) check(t testing.TB, got []CrackerResult) {
	t.Helper()
	if len(got) != len(f.want) {
		t.Fatalf("got %d results, want %d", len(got), len(f.want))
	}
	for i := range got {
		if got[i] != f.want[i] {
			t.Fatalf("got %+v, want %+v", got[i], f.want[i])
		}
	}
}

func BenchmarkCrackWorkerPipeline(b *testing.B) {
	for _, w := range workerWorkloads {
		b.Run(w.name, func(b *testing.B) {
			fixture := newWorkerFixture(b, w)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				fixture.check(b, fixture.run())
			}
		})
	}
}
