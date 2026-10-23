package cracker

import "testing"

var shaWorkerWorkloads = func() []workerWorkload {
	var workloads []workerWorkload
	for _, family := range []string{"sha1", "sha256"} {
		for _, original := range workerWorkloads {
			w := original
			w.family = family
			w.name = family + "_" + w.name
			workloads = append(workloads, w)
		}
	}
	return workloads
}()

func BenchmarkSHAWorkerPipeline(b *testing.B) {
	for _, w := range shaWorkerWorkloads {
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

func TestSHAWorkerPipeline(t *testing.T) {
	for _, w := range shaWorkerWorkloads {
		t.Run(w.name, func(t *testing.T) { fixture := newWorkerFixture(t, w); fixture.check(t, fixture.run()) })
	}
}
