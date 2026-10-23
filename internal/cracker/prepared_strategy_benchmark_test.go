package cracker

import "testing"

var preparedStrategySink crackStrategies

var preparedWorkloads = []workerWorkload{
	{family: "sha256", name: "sha256_1x1", mode: "fixed", targets: 1, plains: 1, workers: 1, mixed: true},
	{family: "sha256", name: "sha256_1000x1", mode: "fixed", targets: 1000, plains: 1, workers: 1, mixed: true},
	{family: "sha256", name: "sha256_1000x20", mode: "fixed", targets: 1000, plains: 20, workers: 4, mixed: true},
	{family: "sha256", name: "sha256_1000x1000", mode: "fixed", targets: 1000, plains: 1000, workers: 4, mixed: true},
	{family: "sha256", name: "sha256_100000x1", mode: "fixed", targets: 100000, plains: 1, workers: 4, mixed: true},
}

func BenchmarkPrepareCrackStrategies(b *testing.B) {
	for _, family := range []string{"md5", "sha1", "sha256"} {
		for _, count := range []int{1, 1000, 100000} {
			w := workerWorkload{family: family, targets: count, plains: 1, workers: 1, mixed: true, mode: "mixed"}
			f := newWorkerFixture(b, w)
			b.Run(family+"/"+fmtCount(count), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					preparedStrategySink = f.engine.prepareCrackStrategies(f.targets, f.algorithms)
				}
			})
		}
	}
}

func fmtCount(n int) string {
	switch n {
	case 1:
		return "n1"
	case 1000:
		return "n1000"
	default:
		return "n100000"
	}
}

func BenchmarkPreparedPipeline(b *testing.B) {
	for _, w := range preparedWorkloads {
		b.Run(w.name, func(b *testing.B) {
			f := newWorkerFixture(b, w)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				f.check(b, f.run())
			}
		})
	}
}

func TestPreparedPipelineSizes(t *testing.T) {
	for _, w := range preparedWorkloads {
		if w.targets > 1000 || w.plains > 20 {
			continue
		}
		t.Run(w.name, func(t *testing.T) { f := newWorkerFixture(t, w); f.check(t, f.run()) })
	}
}
