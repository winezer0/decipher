package cracker

import (
	"fmt"
	"testing"

	"github.com/winezer0/xutils/logging"
)

func BenchmarkUnusedPassDispatch(b *testing.B) {
	if err := logging.InitDefaultLogger(logging.LogConfig{Level: "error", ConsoleFormat: "LCM"}); err != nil {
		b.Fatal(err)
	}
	for _, mode := range []string{"fixed", "dynamic", "rejected"} {
		for _, plains := range []int{4, 10000} {
			b.Run(fmt.Sprintf("%s/p%d", mode, plains), func(b *testing.B) {
				f := newWorkerFixture(b, workerWorkload{family: "sha256", mode: "dynamic", targets: 3, plains: plains, workers: 4, mixed: true})
				switch mode {
				case "fixed":
					f.algorithms = f.algorithms[:1]
				case "dynamic":
					f.algorithms = f.algorithms[1:2]
				case "rejected":
					for i := range f.targets {
						f.targets[i].Hash = "invalid"
					}
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					f.check(b, f.run())
				}
			})
		}
	}
}
