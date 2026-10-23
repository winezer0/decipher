package algo_test

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"github.com/winezer0/decipher/internal/algo"
	hashmd5 "github.com/winezer0/decipher/internal/algo/md5"
	hashsha "github.com/winezer0/decipher/internal/algo/sha"
	"github.com/winezer0/decipher/internal/algo/types"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
)

var digestAlgorithms = []algo.Algorithm{
	&hashmd5.MD5Algo{}, &hashmd5.MD5SaltPassAlgo{}, &hashmd5.MD5PassSaltAlgo{},
	&hashsha.SHA1Algo{}, &hashsha.SHA1SaltPassAlgo{}, &hashsha.SHA1PassSaltAlgo{},
	&hashsha.SHA256Algo{}, &hashsha.SHA256SaltPassAlgo{}, &hashsha.SHA256PassSaltAlgo{},
}

func digestReference(a algo.Algorithm, plain, salt string) string {
	input := plain
	if strings.Contains(a.Name(), "($salt.$pass)") {
		input = salt + plain
	} else if strings.Contains(a.Name(), "($pass.$salt)") {
		input = plain + salt
	}
	if strings.HasPrefix(a.Name(), "md5(") {
		sum := md5.Sum([]byte(input))
		return hex.EncodeToString(sum[:])
	}
	if strings.HasPrefix(a.Name(), "sha1(") {
		sum := sha1.Sum([]byte(input))
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

func TestPreparedDigestMatchesRecover(t *testing.T) {
	for _, a := range digestAlgorithms {
		t.Run(a.Name(), func(t *testing.T) {
			recover, _ := algo.PrepareRecover(a)
			if recover == nil {
				t.Fatal("missing prepared implementation")
			}
			inputs := [][2]string{{"", ""}, {"plain", "salt"}, {"中文🙂\x00", "盐\x00"}, {string([]byte{0xff, 0, 0x80}), string([]byte{0xfe, 0})}}
			for _, size := range []int{1, 31, 32, 33, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 4096} {
				inputs = append(inputs, [2]string{strings.Repeat("p", size), ""}, [2]string{"", strings.Repeat("s", size)}, [2]string{strings.Repeat("p", size/2), strings.Repeat("s", size-size/2)})
			}
			for _, input := range inputs {
				plain, salt := input[0], input[1]
				token := digestReference(a, plain, salt)
				mixed := []byte(token)
				for i := 0; i < len(mixed); i += 2 {
					if mixed[i] >= 'a' && mixed[i] <= 'f' {
						mixed[i] -= 'a' - 'A'
					}
				}
				tokens := []string{token, strings.ToUpper(token), string(mixed), "", token[:len(token)-1], token + "0", " " + token, token + "\n", strings.Repeat("g", len(token)), "\x00" + token[1:], "é" + token[2:], strings.Repeat("Ｆ", len(token)), digestReference(a, plain+"wrong", salt)}
				for i, stored := range tokens {
					target := algo.DecodeDigest(stored)
					got, err := recover(&target, salt, plain)
					ordinary, ordinaryErr := a.Recover(stored, salt, plain)
					if got != ordinary || err != ordinaryErr {
						t.Fatalf("prepared differs for token %q: %q %v vs %q %v", stored, got, err, ordinary, ordinaryErr)
					}
					if i < 3 {
						if err != nil || got != plain {
							t.Fatal("valid digest rejected")
						}
					} else if got != "" || err != types.ErrVerificationFailed {
						t.Fatal("invalid digest accepted")
					}
				}
			}
		})
	}
}

type wrappedMD5 struct{ hashmd5.MD5Algo }

func (*wrappedMD5) Recover(string, string, string) (string, error) { return "wrapped", nil }

type wrappedSHA256 struct{ hashsha.SHA256Algo }

func (*wrappedSHA256) Recover(string, string, string) (string, error) { return "wrapped", nil }

func TestPreparedRecoverExactTypes(t *testing.T) {
	for _, a := range []algo.Algorithm{&wrappedMD5{}, &wrappedSHA256{}, &hashsha.SHA512Algo{}, &hashmd5.MD5DoubleAlgo{}} {
		if recover, _ := algo.PrepareRecover(a); recover != nil {
			t.Fatalf("unexpected preparation for %T", a)
		}
	}
}

func TestPreparedIdentifyMatchesAlgorithms(t *testing.T) {
	for _, a := range digestAlgorithms {
		_, length := algo.PrepareRecover(a)
		valid := digestReference(a, "plain", "salt")
		for _, token := range []string{valid, strings.ToUpper(valid), "", valid[:len(valid)-1], valid + "0", strings.Repeat("g", len(valid)), "\x00" + valid[1:], "é" + valid[2:], strings.Repeat("a", 32), strings.Repeat("a", 40), strings.Repeat("a", 64)} {
			prepared := algo.DecodeDigest(token)
			if got := len(token) == length && prepared.Valid(); got != a.Identify(token) {
				t.Fatalf("Identify differs for %s token %q", a.Name(), token)
			}
		}
	}
}

func TestPreparedDigestConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for _, a := range digestAlgorithms {
		recover, _ := algo.PrepareRecover(a)
		plain, salt := "shared\x00中文", "salt"
		target := algo.DecodeDigest(strings.ToUpper(digestReference(a, plain, salt)))
		original := target
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 100; i++ {
					got, err := recover(&target, salt, plain)
					if got != plain || err != nil {
						t.Errorf("concurrent %s failed", a.Name())
						return
					}
					got, err = recover(&target, salt, plain+"wrong")
					if got != "" || err != types.ErrVerificationFailed {
						t.Errorf("concurrent %s invalid match", a.Name())
						return
					}
				}
			}()
		}
		wg.Wait()
		if target != original {
			t.Fatalf("shared target changed for %s", a.Name())
		}
	}
}

var preparedResultSink string

func BenchmarkPreparedRecover(b *testing.B) {
	for _, a := range digestAlgorithms {
		for _, size := range []int{8, 64, 4096} {
			plain, salt := strings.Repeat("p", size), "0123456789abcdef"
			token := digestReference(a, plain, salt)
			target := algo.DecodeDigest(token)
			recover, _ := algo.PrepareRecover(a)
			for _, mode := range []string{"ordinary", "prepared"} {
				for _, hit := range []bool{false, true} {
					candidate := plain
					if !hit {
						candidate += "wrong"
					}
					b.Run(fmt.Sprintf("%s/n%d/%s/hit%t", a.Name(), size, mode, hit), func(b *testing.B) {
						b.ReportAllocs()
						b.ResetTimer()
						for i := 0; i < b.N; i++ {
							var got string
							var err error
							if mode == "prepared" {
								got, err = recover(&target, salt, candidate)
							} else {
								got, err = a.Recover(token, salt, candidate)
							}
							if hit {
								if err != nil || got != candidate {
									b.Fatal("invalid hit")
								}
							} else if err != types.ErrVerificationFailed || got != "" {
								b.Fatal("invalid miss")
							}
							preparedResultSink = got
						}
					})
				}
			}
		}
	}
}
