package cracker

import (
	"context"
	"crypto/md5"
	"decipher/internal/algo"
	md5algo "decipher/internal/algo/md5"
	"fmt"
	"strings"
	"testing"
	"time"
)

func batchTestSalts(count int) []string {
	salts := make([]string, count)
	for i := range salts {
		salts[i] = fmt.Sprintf("salt-%d", i)
	}
	return salts
}

func TestProcessBatchSharesImmutableSaltBatches(t *testing.T) {
	for _, count := range []int{0, 1, 999, 1000, 1001, 2001} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			plains := []string{"first", "second", "third"}
			salts := batchTestSalts(count)
			batches := (count + 999) / 1000
			tasks := make(chan crackTask, len(plains)*(batches+1))
			engine := &Engine{}
			engine.processBatch(context.Background(), tasks, plains, []SaltProvider{NewMemorySaltProvider(salts, "test")}, nil)
			close(tasks)
			// Inspect only after every batch has been published, catching array reuse.
			var got []crackTask
			for task := range tasks {
				got = append(got, task)
			}
			if len(got) != len(plains)*(batches+1) {
				t.Fatalf("incorrect task count: %d", len(got))
			}
			for i, plain := range plains {
				if got[i].plainLine != plain || got[i].salts != nil {
					t.Fatalf("incorrect fixed task: %#v", got[i])
				}
			}
			for batch := 0; batch < batches; batch++ {
				start, end := batch*1000, min((batch+1)*1000, count)
				first := got[len(plains)*(batch+1)]
				for i, plain := range plains {
					task := got[len(plains)*(batch+1)+i]
					if task.plainLine != plain || len(task.salts) != end-start {
						t.Fatalf("incorrect batch %d task: %#v", batch, task)
					}
					for j, salt := range task.salts {
						if salt != salts[start+j] {
							t.Fatalf("batch %d salt %d changed: %q", batch, j, salt)
						}
					}
					if &task.salts[0] != &first.salts[0] {
						t.Fatal("tasks in the same batch do not share storage")
					}
				}
				if batch > 0 && &first.salts[0] == &got[len(plains)*batch].salts[0] {
					t.Fatal("published batch storage was reused")
				}
			}
		})
	}
}

func TestSharedSaltBatchesConcurrentCracking(t *testing.T) {
	salts := batchTestSalts(2001)
	var targets []HashSaltTarget
	want := make(map[string]string)
	for _, i := range []int{0, 999, 1000, 1999, 2000} {
		hash := fmt.Sprintf("%x", md5.Sum([]byte(salts[i]+"password")))
		targets = append(targets, HashSaltTarget{Hash: hash})
		want[hash] = salts[i]
	}
	engine := &Engine{workers: 4}
	results := engine.runHashCrackWithDictStream(targets, []algo.Algorithm{&md5algo.MD5SaltPassAlgo{}},
		[]SaltProvider{NewMemorySaltProvider(salts, "test")}, strings.NewReader("wrong\npassword\nwrong-again\n"), time.Now(), nil)
	if len(results) != len(want) {
		t.Fatalf("got %d results, want %d: %#v", len(results), len(want), results)
	}
	for _, result := range results {
		salt, ok := want[result.Hash]
		if !ok || result.Salt != salt || result.Plaintext != "password" {
			t.Fatalf("incorrect result: %#v", result)
		}
		delete(want, result.Hash)
	}
}

// Measures dispatch and allocation only; it excludes algorithm cost and console I/O.
func BenchmarkProcessBatchSaltDispatch(b *testing.B) {
	for _, saltCount := range []int{1000, 2500} {
		b.Run(fmt.Sprintf("plains=10000/salts=%d", saltCount), func(b *testing.B) {
			plains := make([]string, 10000)
			for i := range plains {
				plains[i] = fmt.Sprintf("plain-%d", i)
			}
			providers := []SaltProvider{NewMemorySaltProvider(batchTestSalts(saltCount), "benchmark")}
			engine := &Engine{}
			expected := len(plains) * (1 + (saltCount+999)/1000)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				tasks := make(chan crackTask, 4)
				done := make(chan int, 1)
				go func() {
					count := 0
					for range tasks {
						count++
					}
					done <- count
				}()
				engine.processBatch(context.Background(), tasks, plains, providers, nil)
				close(tasks)
				if count := <-done; count != expected {
					b.Fatalf("got %d tasks, want %d", count, expected)
				}
			}
		})
	}
}
