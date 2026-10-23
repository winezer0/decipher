package cracker

import (
	"fmt"
	"strings"
	"testing"
)

func saltedLongFixture(t testing.TB, family string) workerFixture {
	f := newWorkerFixture(t, workerWorkload{family: family, mode: "mixed", targets: 100, plains: 20, workers: 4, mixed: true, affix: true})
	// 盐及原始明文保持原夹具不变，长前缀确保两种加盐路径均走长输入回退。
	f.engine.PassPrefix = strings.Repeat("p", 4096)
	return f
}

func BenchmarkSaltedLongWorkerPipeline(b *testing.B) {
	for _, family := range []string{"md5", "sha1", "sha256"} {
		b.Run(family, func(b *testing.B) {
			f := saltedLongFixture(b, family)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				f.check(b, f.run())
			}
		})
	}
}

func TestSaltedWorkerThresholdResults(t *testing.T) {
	for _, family := range []string{"md5", "sha1", "sha256"} {
		for _, size := range []int{32, 33, 64, 128, 256, 257, 4096} {
			for _, index := range []int{1, 2} {
				t.Run(fmt.Sprintf("%s/n%d/algo%d", family, size, index), func(t *testing.T) {
					f := newWorkerFixture(t, workerWorkload{family: family, mode: "mixed", targets: 4, plains: 3, workers: 4, mixed: true})
					f.algorithms = f.algorithms[index : index+1]
					f.engine.PassPrefix = strings.Repeat("p", size-22)
					f.engine.SaltPrefix = "s:"
					plain := f.engine.AffixPasswd("candidate-00000002")
					salt := "s0"
					hash, err := f.algorithms[0].Seal(plain, f.engine.AffixSalt(salt))
					if err != nil {
						t.Fatal(err)
					}
					f.targets = []HashSaltTarget{{Hash: hash, Salt: salt}, {Hash: hash}}
					// 不依赖 Worker 结果顺序；分别确认固定盐及动态盐目标都正确命中。
					got := f.run()
					if len(got) != 2 {
						t.Fatalf("got %d results", len(got))
					}
					seen := map[string]bool{}
					for _, r := range got {
						key := r.Hash + ":" + r.Salt
						if r.Hash != hash || r.Salt != salt || r.Plaintext != plain || r.Algorithm != f.algorithms[0].Name() || r.AlgoType != "static" {
							t.Fatalf("unexpected result: %+v", r)
						}
						seen[key] = true
					}
					if len(seen) != 1 {
						t.Fatal("logical targets changed")
					}
				})
			}
		}
	}
}
