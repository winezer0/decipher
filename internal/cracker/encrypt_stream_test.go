package cracker

import (
	"github.com/winezer0/decipher/internal/algo"
	"github.com/winezer0/decipher/internal/algo/md5"
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestEncryptStreamMatchesCollectedResults(t *testing.T) {
	plains := []string{mustWriteTempFileLines(t, []string{"文本,\"", "second"})}
	salts := []string{mustWriteTempFileLines(t, []string{"盐", "s2"})}
	algos := []algo.Algorithm{&md5.MD5Algo{}, &md5.MD5SaltPassAlgo{}}
	for _, workers := range []int{1, 4} {
		engine := NewEngine(workers, t.TempDir(), "")
		want := engine.RunEncrypt(plains, salts, algos)
		var got []string
		if err := engine.RunEncryptStream(plains, salts, algos, func(result EncryptResult) error {
			got = append(got, result.String())
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		sort.Strings(want)
		sort.Strings(got)
		if len(got) != 8 || !reflect.DeepEqual(got, want) {
			t.Fatalf("workers=%d got=%v want=%v", workers, got, want)
		}
	}
}

func TestEncryptStreamConsumerFailureCancels(t *testing.T) {
	for _, salted := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "salted"}[salted], func(t *testing.T) {
			engine := NewEngine(4, t.TempDir(), "")
			plainLines := make([]string, 20000)
			for i := range plainLines {
				plainLines[i] = "text"
			}
			plains := []string{mustWriteTempFileLines(t, plainLines)}
			algos := []algo.Algorithm{&md5.MD5Algo{}}
			var salts []string
			if salted {
				algos = []algo.Algorithm{&md5.MD5SaltPassAlgo{}}
				salts = []string{"gen:1:20:ab"}
			}
			failure := errors.New("consumer stopped")
			done := make(chan error, 1)
			calls := 0
			go func() {
				done <- engine.RunEncryptStream(plains, salts, algos, func(EncryptResult) error { calls++; return failure })
			}()
			select {
			case err := <-done:
				if !errors.Is(err, failure) || calls != 1 {
					t.Fatalf("error=%v calls=%d", err, calls)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("stream did not cancel")
			}
		})
	}
}

func TestEncryptStreamEmpty(t *testing.T) {
	engine := NewEngine(2, t.TempDir(), "")
	if err := engine.RunEncryptStream(nil, nil, []algo.Algorithm{&md5.MD5Algo{}}, func(EncryptResult) error { t.Fatal("unexpected result"); return nil }); err != nil {
		t.Fatal(err)
	}
}

type blockedEncryptSaltProvider struct {
	blocked, done chan struct{}
}

func (*blockedEncryptSaltProvider) Name() string { return "blocked-test" }
func (*blockedEncryptSaltProvider) Count() int64 { return 10000 }
func (p *blockedEncryptSaltProvider) GenerateStream(stop <-chan struct{}) <-chan string {
	out := make(chan string)
	go func() {
		defer close(p.done)
		defer close(out)
		for i := 0; i < 10000; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i == 1001 {
				close(p.blocked)
			}
			out <- "salt"
		}
	}()
	return out
}

func TestEncryptMultiSaltCancellationReleasesBlockedProvider(t *testing.T) {
	provider := &blockedEncryptSaltProvider{blocked: make(chan struct{}), done: make(chan struct{})}
	stop := make(chan struct{})
	stream := NewMultiSaltProvider([]SaltProvider{provider}).GenerateStream(stop)
	select {
	case <-provider.blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("provider did not reach blocked send")
	}
	close(stop)
	// 此时不消费外层通道，保证组合提供者必须走取消分支，释放子提供者。
	select {
	case <-provider.done:
	case <-time.After(5 * time.Second):
		t.Fatal("child provider leaked after cancellation")
	}
	for range stream {
	}
}
