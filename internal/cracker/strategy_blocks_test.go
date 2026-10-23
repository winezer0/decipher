package cracker

import (
	"github.com/winezer0/decipher/internal/algo"
	"github.com/winezer0/decipher/internal/algo/sha"
	"fmt"
	"reflect"
	"testing"
)

func TestStrategyBlocksKeepTargetAndAlgorithmOrder(t *testing.T) {
	for _, count := range []int{1, 15, 16, 85, 86, 1000} {
		for _, repeats := range []int{1, 4} {
			t.Run(fmt.Sprintf("%d/%d", count, repeats), func(t *testing.T) {
				var calls []string
				wrapper := &identifyPreparedSHA256{calls: &calls}
				var algorithms []algo.Algorithm
				for i := 0; i < repeats; i++ {
					algorithms = append(algorithms, &sha.SHA256Algo{}, &sha.SHA256SaltPassAlgo{}, &sha.SHA256PassSaltAlgo{})
				}
				algorithms = append(algorithms, wrapper)
				targets := make([]HashSaltTarget, count)
				var wantCalls []string
				for i := range targets {
					targets[i].Hash = fmt.Sprintf("%064x", i+1)
					if i%2 == 0 {
						targets[i].Salt = "s"
					}
					wantCalls = append(wantCalls, targets[i].Hash)
				}
				got := (&Engine{}).prepareCrackStrategies(targets, algorithms)
				if !reflect.DeepEqual(calls, wantCalls) {
					t.Fatal("Identify calls changed")
				}
				for _, pass := range []struct {
					dynamic    bool
					strategies []crackStrategy
				}{{false, got.fixed}, {true, got.dynamic}} {
					index := 0
					for _, target := range targets {
						var want []algo.Algorithm
						for _, a := range algorithms[:len(algorithms)-1] {
							if (target.Salt == "" && a.NeedSalt()) == pass.dynamic {
								want = append(want, a)
							}
						}
						if len(want) == 0 {
							continue
						}
						if index >= len(pass.strategies) {
							t.Fatal("missing target")
						}
						s := pass.strategies[index]
						index++
						if s.target != target || len(s.validAlgos) != len(want) {
							t.Fatal("target changed")
						}
						for i, a := range want {
							if s.validAlgos[i].Algorithm != a {
								t.Fatal("algorithm order changed")
							}
						}
					}
					if index != len(pass.strategies) {
						t.Fatal("extra targets")
					}
				}
			})
		}
	}
}
