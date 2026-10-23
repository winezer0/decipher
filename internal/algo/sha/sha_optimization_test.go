package sha

import (
	"crypto/sha1"
	"crypto/sha256"
	"decipher/internal/algo/types"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
)

type measuredSHAAlgorithm interface {
	Name() string
	Seal(string, string) (string, error)
	Recover(string, string, string) (string, error)
}

var measuredSHAAlgorithms = []measuredSHAAlgorithm{&SHA1Algo{}, &SHA1SaltPassAlgo{}, &SHA1PassSaltAlgo{}, &SHA256Algo{}, &SHA256SaltPassAlgo{}, &SHA256PassSaltAlgo{}}
var shaBenchmarkString string

func referenceSHA(a measuredSHAAlgorithm, plain, salt string) string {
	input := plain
	if strings.Contains(a.Name(), "($salt.$pass)") {
		input = salt + plain
	} else if strings.Contains(a.Name(), "($pass.$salt)") {
		input = plain + salt
	}
	if strings.HasPrefix(a.Name(), "sha1(") {
		sum := sha1.Sum([]byte(input))
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

func TestSHAOptimizedCompatibility(t *testing.T) {
	lengths := []int{0, 1, 31, 32, 33, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 4096}
	for _, a := range measuredSHAAlgorithms {
		t.Run(a.Name(), func(t *testing.T) {
			pairs := [][2]string{{"中文🙂\x00password", "盐\x00值"}, {string([]byte{0xff, 0xfe, 0, 1}), string([]byte{0x80, 0xff})}}
			for _, n := range lengths {
				pairs = append(pairs, [2]string{strings.Repeat("a", n), ""}, [2]string{"", strings.Repeat("b", n)}, [2]string{strings.Repeat("p", n), strings.Repeat("s", 17)})
				// 组合长度覆盖 SHA 分块边界，以及可能使用的短输入边界。
				if n > 0 {
					pairs = append(pairs, [2]string{strings.Repeat("p", n/2), strings.Repeat("s", n-n/2)})
				}
			}
			for _, pair := range pairs {
				plain, salt := pair[0], pair[1]
				want := referenceSHA(a, plain, salt)
				got, err := a.Seal(plain, salt)
				if err != nil || got != want {
					t.Fatalf("Seal lengths %d/%d: %q %v want %q", len(plain), len(salt), got, err, want)
				}
				mixed := []byte(want)
				for i := 0; i < len(mixed); i += 2 {
					if mixed[i] >= 'a' && mixed[i] <= 'f' {
						mixed[i] -= 'a' - 'A'
					}
				}
				for _, token := range []string{want, strings.ToUpper(want), string(mixed)} {
					recovered, err := a.Recover(token, salt, plain)
					if err != nil || recovered != plain {
						t.Fatalf("Recover match: %q %v", recovered, err)
					}
				}
				for _, token := range []string{"", want[:len(want)-1], want + "0", " " + want, want + "\n", strings.Repeat("g", len(want)), "\x00" + want[1:], "é" + want[2:], strings.Repeat("Ｆ", len(want)), referenceSHA(a, plain+"wrong", salt)} {
					recovered, err := a.Recover(token, salt, plain)
					if recovered != "" || err != types.ErrVerificationFailed {
						t.Fatalf("Recover invalid %q: %q %v", token, recovered, err)
					}
				}
			}
		})
	}
}

func TestSHAOptimizedConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				plain, salt := fmt.Sprintf("candidate-%d-%d", g, i), fmt.Sprintf("salt-%d", g)
				for _, a := range measuredSHAAlgorithms {
					want := referenceSHA(a, plain, salt)
					got, err := a.Seal(plain, salt)
					if err != nil || got != want {
						t.Errorf("Seal mismatch: %s", a.Name())
						return
					}
					got, err = a.Recover(strings.ToUpper(want), salt, plain)
					if err != nil || got != plain {
						t.Errorf("Recover mismatch: %s", a.Name())
						return
					}
				}
			}
		}(g)
	}
	wg.Wait()
}

func BenchmarkSHAOperations(b *testing.B) {
	for _, a := range measuredSHAAlgorithms {
		for _, size := range []int{8, 64, 4096} {
			plain, salt := strings.Repeat("p", size), "0123456789abcdef"
			token := referenceSHA(a, plain, salt)
			for _, op := range []string{"seal", "hit", "miss", "upper"} {
				b.Run(fmt.Sprintf("%s/n%d/%s", a.Name(), size, op), func(b *testing.B) {
					target := token
					if op == "miss" {
						target = referenceSHA(a, plain+"wrong", salt)
					}
					if op == "upper" {
						target = strings.ToUpper(token)
					}
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if op == "seal" {
							got, err := a.Seal(plain, salt)
							if err != nil || got != token {
								b.Fatal("invalid Seal")
							}
							shaBenchmarkString = got
						} else {
							got, err := a.Recover(target, salt, plain)
							if op == "miss" {
								if err != types.ErrVerificationFailed || got != "" {
									b.Fatal("invalid miss")
								}
							} else if err != nil || got != plain {
								b.Fatal("invalid hit")
							}
							shaBenchmarkString = got
						}
					}
				})
			}
		}
	}
}

var shaDigestSink []byte

func BenchmarkSHADigestMethods(b *testing.B) {
	for _, family := range []string{"sha1", "sha256"} {
		for _, size := range []int{8, 64, 4096} {
			plain, salt := strings.Repeat("p", size), "0123456789abcdef"
			for _, method := range []string{"sum", "split"} {
				b.Run(fmt.Sprintf("%s/n%d/%s", family, size, method), func(b *testing.B) {
					var want [sha256.Size]byte
					if family == "sha1" {
						d := sha1.Sum([]byte(salt + plain))
						copy(want[:], d[:])
					} else {
						want = sha256.Sum256([]byte(salt + plain))
					}
					var result [sha256.Size]byte
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if method == "sum" {
							if family == "sha1" {
								d := sha1.Sum([]byte(salt + plain))
								copy(result[:], d[:])
							} else {
								result = sha256.Sum256([]byte(salt + plain))
							}
						} else if family == "sha1" {
							h := sha1.New()
							h.Write([]byte(salt))
							h.Write([]byte(plain))
							h.Sum(result[:0])
						} else {
							h := sha256.New()
							h.Write([]byte(salt))
							h.Write([]byte(plain))
							h.Sum(result[:0])
						}
					}
					if result != want {
						b.Fatal("invalid digest")
					}
					shaDigestSink = append(shaDigestSink[:0], result[:]...)
				})
			}
		}
	}
}
