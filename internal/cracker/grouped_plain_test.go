package cracker

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"github.com/winezer0/decipher/internal/algo"
	md5algo "github.com/winezer0/decipher/internal/algo/md5"
	"github.com/winezer0/decipher/internal/algo/sha"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func groupedPlainResults(e *Engine, strategies crackStrategies, count int) []CrackerResult {
	jobs := make(chan crackTask, 3)
	for _, plain := range []string{"first", "second", strings.Repeat("x", 70000)} {
		jobs <- crackTask{plainLine: plain}
	}
	close(jobs)
	out := make(chan CrackerResult, 3*count)
	e.crackWorker(context.Background(), jobs, out, strategies)
	close(out)
	var results []CrackerResult
	for result := range out {
		results = append(results, result)
	}
	return results
}

func TestGroupedPlainMatchesPerTargetVerification(t *testing.T) {
	for _, family := range []string{"md5", "sha1", "sha256"} {
		for _, count := range []int{1, 15, 16, 100, 1000} {
			t.Run(fmt.Sprintf("%s/%d", family, count), func(t *testing.T) {
				var algorithm algo.Algorithm = &md5algo.MD5Algo{}
				if family == "sha1" {
					algorithm = &sha.SHA1Algo{}
				} else if family == "sha256" {
					algorithm = &sha.SHA256Algo{}
				}
				e := &Engine{PassPrefix: "pre-", PassSuffix: "-post", SaltPrefix: "ignored:"}
				targets := make([]HashSaltTarget, count)
				for i := range targets {
					plain := []string{"first", "second", strings.Repeat("x", 70000), "miss"}[i%4]
					input := []byte("pre-" + plain + "-post")
					var hash string
					switch family {
					case "md5":
						hash = fmt.Sprintf("%x", md5.Sum(input))
					case "sha1":
						hash = fmt.Sprintf("%x", sha1.Sum(input))
					case "sha256":
						hash = fmt.Sprintf("%x", sha256.Sum256(input))
					}
					if i%2 == 0 {
						hash = strings.ToUpper(hash)
					}
					targets[i] = HashSaltTarget{Hash: hash, Salt: fmt.Sprintf("metadata%d", i%3)}
				}
				targets = append(targets, HashSaltTarget{Hash: "invalid"})
				strategies := e.prepareCrackStrategies(targets, []algo.Algorithm{algorithm})
				got := groupedPlainResults(e, strategies, len(targets))
				strategies.fixedPlainDigest = nil
				want := groupedPlainResults(e, strategies, len(targets))
				if !reflect.DeepEqual(got, want) || len(got) == 0 {
					t.Fatalf("results differ: got %d want %d", len(got), len(want))
				}
			})
		}
	}
}

func TestGroupedPlainKeepsCustomRecover(t *testing.T) {
	calls := 0
	a := &workerProbeAlgo{label: "custom", recover: func(_, _, plain string) (string, error) { calls++; return "custom:" + plain, nil }}
	targets := make([]HashSaltTarget, 32)
	for i := range targets {
		targets[i].Hash = fmt.Sprintf("%032x", i)
	}
	e := &Engine{}
	strategies := e.prepareCrackStrategies(targets, []algo.Algorithm{a})
	got := groupedPlainResults(e, strategies, len(targets))
	if calls != 96 || len(got) != 96 {
		t.Fatal("custom Recover bypassed")
	}
	for _, r := range got {
		if !strings.HasPrefix(r.Plaintext, "custom:") {
			t.Fatal("custom result changed")
		}
	}
}

func TestGroupedPlainFallsBackForMixedAlgorithms(t *testing.T) {
	plain := "first"
	md5Hash := fmt.Sprintf("%x", md5.Sum([]byte(plain)))
	sha256Hash := fmt.Sprintf("%x", sha256.Sum256([]byte(plain)))
	targets := make([]HashSaltTarget, 16)
	for i := range targets {
		if i%2 == 0 {
			targets[i].Hash = md5Hash
		} else {
			targets[i].Hash = sha256Hash
		}
	}
	algorithms := []algo.Algorithm{&md5algo.MD5Algo{}, &sha.SHA256Algo{}}
	strategies := (&Engine{}).prepareCrackStrategies(targets, algorithms)
	if strategies.fixedPlainDigest != nil {
		t.Fatal("mixed algorithms must use per-target verification")
	}
	got := groupedPlainResults(&Engine{}, strategies, len(targets))
	if len(got) != len(targets) {
		t.Fatalf("got %d results want %d", len(got), len(targets))
	}
	for i, result := range got {
		if result.Hash != targets[i].Hash || result.Plaintext != plain {
			t.Errorf("result %d = %+v; target order or plaintext changed", i, result)
		}
		wantAlgorithm := algorithms[0].Name()
		if i%2 == 1 {
			wantAlgorithm = algorithms[1].Name()
		}
		if result.Algorithm != wantAlgorithm {
			t.Errorf("result %d algorithm = %q want %q", i, result.Algorithm, wantAlgorithm)
		}
	}
}

func TestGroupedPlainCancelsBlockedResult(t *testing.T) {
	targets := make([]HashSaltTarget, 16)
	for i := range targets {
		targets[i].Hash = fmt.Sprintf("%x", sha256.Sum256([]byte("first")))
	}
	e := &Engine{}
	strategies := e.prepareCrackStrategies(targets, []algo.Algorithm{&sha.SHA256Algo{}})
	compute := strategies.fixedPlainDigest
	computed := make(chan struct{})
	strategies.fixedPlainDigest = func(plain string) algo.PreparedDigest { sum := compute(plain); close(computed); return sum }
	jobs := make(chan crackTask, 1)
	jobs <- crackTask{plainLine: "first"}
	close(jobs)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); e.crackWorker(ctx, jobs, make(chan CrackerResult), strategies) }()
	select {
	case <-computed:
	case <-time.After(5 * time.Second):
		t.Fatal("candidate not computed")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked result did not cancel")
	}
}
