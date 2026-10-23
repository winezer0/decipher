package cracker

import (
	"crypto/sha256"
	"decipher/internal/algo"
	hashsha "decipher/internal/algo/sha"
	"decipher/internal/algo/types"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

type wrappedPreparedSHA256 struct {
	hashsha.SHA256Algo
	calls *[]string
	hit   bool
}

func (a *wrappedPreparedSHA256) Recover(token, salt, plain string) (string, error) {
	*a.calls = append(*a.calls, token+"/"+salt+"/"+plain)
	if a.hit {
		return "wrapped:" + plain, nil
	}
	return "", types.ErrVerificationFailed
}

func TestPreparedWorkerPreservesWrappedRecover(t *testing.T) {
	for _, hit := range []bool{false, true} {
		e := &Engine{workers: 1, PassPrefix: "pre-", SaltPrefix: "s:"}
		plain := "pre-candidate"
		token := strings.ToUpper(fmt.Sprintf("%x", sha256.Sum256([]byte(plain))))
		var calls []string
		wrapped := &wrappedPreparedSHA256{calls: &calls, hit: hit}
		targets := []HashSaltTarget{{Hash: token, Salt: "one"}, {Hash: token, Salt: "two"}, {Hash: token, Salt: "one"}}
		algorithms := []algo.Algorithm{wrapped, &hashsha.SHA256Algo{}}
		got := e.runHashCrackWithDictStream(targets, algorithms, nil, strings.NewReader("candidate\n"), time.Now(), nil)
		if len(got) != len(targets) {
			t.Fatalf("got %d results", len(got))
		}
		for i, res := range got {
			wantPlain := plain
			if hit {
				wantPlain = "wrapped:" + plain
			}
			if res.Hash != token || res.Salt != targets[i].Salt || res.Plaintext != wantPlain || res.Algorithm != "sha256($pass)" || res.AlgoType != "static" {
				t.Fatalf("unexpected result: %+v", res)
			}
		}
		var wantCalls []string
		for _, target := range targets {
			wantCalls = append(wantCalls, token+"/s:"+target.Salt+"/"+plain)
		}
		if !reflect.DeepEqual(calls, wantCalls) {
			t.Fatalf("wrapped Recover bypassed: %v want %v", calls, wantCalls)
		}
	}
}

func TestPreparedWorkerIndependentRuns(t *testing.T) {
	done := make(chan struct{}, 4)
	for i := 0; i < 4; i++ {
		go func(run int) {
			defer func() { done <- struct{}{} }()
			w := workerWorkload{family: "sha256", targets: 10, plains: 20, workers: 4, mixed: true, affix: true, mode: "fixed", hit: "late"}
			f := newWorkerFixture(t, w)
			f.engine.PassPrefix = fmt.Sprintf("run-%d:", run)
			plain := f.engine.AffixPasswd("candidate-00000019")
			hash, err := f.algorithms[0].Seal(plain, "")
			if err != nil {
				t.Error(err)
				return
			}
			f.targets[0].Hash = hash
			f.want[0].Hash = hash
			f.want[0].Plaintext = plain
			f.check(t, f.run())
		}(i)
	}
	for i := 0; i < 4; i++ {
		<-done
	}
}

type identifyPreparedSHA256 struct {
	hashsha.SHA256Algo
	calls *[]string
}

func (a *identifyPreparedSHA256) Identify(token string) bool {
	*a.calls = append(*a.calls, token)
	return token == "custom-token"
}

func TestPreparedStrategyPreservesWrappedIdentify(t *testing.T) {
	var calls []string
	wrapped := &identifyPreparedSHA256{calls: &calls}
	valid := strings.Repeat("a", 64)
	targets := []HashSaltTarget{{Hash: valid}, {Hash: "custom-token"}, {Hash: strings.Repeat("g", 64)}}
	strategies := (&Engine{}).prepareCrackStrategies(targets, []algo.Algorithm{wrapped, &hashsha.SHA256Algo{}})
	if !reflect.DeepEqual(calls, []string{targets[0].Hash, targets[1].Hash, targets[2].Hash}) {
		t.Fatalf("Identify calls changed: %v", calls)
	}
	if len(strategies.dynamic) != 0 || len(strategies.fixed) != 2 {
		t.Fatalf("unexpected strategy counts: %+v", strategies)
	}
	if strategies.fixed[0].prepared == nil || strategies.fixed[1].prepared != nil || len(strategies.fixed[0].validAlgos) != 1 || len(strategies.fixed[1].validAlgos) != 1 || strategies.fixed[1].validAlgos[0].Algorithm != wrapped {
		t.Fatal("wrapped Identify was bypassed")
	}
}

func TestPreparedStrategySharesTargetAcrossPasses(t *testing.T) {
	target := HashSaltTarget{Hash: strings.Repeat("A", 64)}
	strategies := (&Engine{}).prepareCrackStrategies([]HashSaltTarget{target}, []algo.Algorithm{&hashsha.SHA256Algo{}, &hashsha.SHA256SaltPassAlgo{}, &hashsha.SHA256PassSaltAlgo{}})
	if len(strategies.fixed) != 1 || len(strategies.dynamic) != 1 {
		t.Fatalf("unexpected strategy counts: %+v", strategies)
	}
	fixed, dynamic := strategies.fixed[0], strategies.dynamic[0]
	if fixed.prepared == nil || fixed.prepared != dynamic.prepared || !fixed.prepared.Valid() || fixed.target != target || dynamic.target != target {
		t.Fatal("fixed and dynamic passes must share the same read-only target")
	}
	if len(fixed.validAlgos) != 1 || len(dynamic.validAlgos) != 2 || dynamic.validAlgos[0].Name() != "sha256($salt.$pass)" || dynamic.validAlgos[1].Name() != "sha256($pass.$salt)" {
		t.Fatal("algorithm order changed")
	}
}
