package md5

import (
	stdmd5 "crypto/md5"
	"github.com/winezer0/decipher/internal/algo/types"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
)

type measuredMD5Algorithm interface {
	Name() string
	Seal(string, string) (string, error)
	Recover(string, string, string) (string, error)
}

var measuredMD5Algorithms = []measuredMD5Algorithm{&MD5Algo{}, &MD5SaltPassAlgo{}, &MD5PassSaltAlgo{}}
var md5BenchmarkString string
var md5BenchmarkDigest [stdmd5.Size]byte

func referenceMD5(a measuredMD5Algorithm, plain, salt string) string {
	input := plain
	switch a.Name() {
	case "md5($salt.$pass)":
		input = salt + plain
	case "md5($pass.$salt)":
		input = plain + salt
	}
	sum := stdmd5.Sum([]byte(input))
	return hex.EncodeToString(sum[:])
}

func TestMD5OptimizedCompatibility(t *testing.T) {
	lengths := []int{0, 1, 31, 32, 33, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 4096}
	for _, a := range measuredMD5Algorithms {
		t.Run(a.Name(), func(t *testing.T) {
			pairs := [][2]string{{"中文🙂\x00password", "盐\x00值"}, {string([]byte{0xff, 0xfe, 0, 1}), string([]byte{0x80, 0xff})}}
			for _, n := range lengths {
				pairs = append(pairs, [2]string{strings.Repeat("a", n), ""}, [2]string{"", strings.Repeat("b", n)}, [2]string{strings.Repeat("p", n), strings.Repeat("s", 17)})
				// 组合长度覆盖 MD5 分块边界，以及可能使用的短输入边界。
				if n > 0 {
					pairs = append(pairs, [2]string{strings.Repeat("p", n/2), strings.Repeat("s", n-n/2)})
				}
			}
			for _, pair := range pairs {
				plain, salt := pair[0], pair[1]
				want := referenceMD5(a, plain, salt)
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
				for _, token := range []string{"", want[:31], want + "0", " " + want, want + "\n", strings.Repeat("g", 32), "\x00" + want[1:], "é" + want[2:], strings.Repeat("Ｆ", 32), referenceMD5(a, plain+"wrong", salt)} {
					recovered, err := a.Recover(token, salt, plain)
					if recovered != "" || err != types.ErrVerificationFailed {
						t.Fatalf("Recover invalid %q: %q %v", token, recovered, err)
					}
				}
			}
		})
	}
}

func TestMD5OptimizedConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				plain, salt := fmt.Sprintf("candidate-%d-%d", g, i), fmt.Sprintf("salt-%d", g)
				for _, a := range measuredMD5Algorithms {
					want := referenceMD5(a, plain, salt)
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

func BenchmarkMD5Operations(b *testing.B) {
	for _, a := range measuredMD5Algorithms {
		for _, size := range []int{8, 64, 4096} {
			plain, salt := strings.Repeat("p", size), "0123456789abcdef"
			token := referenceMD5(a, plain, salt)
			for _, op := range []string{"seal", "hit", "miss", "upper"} {
				b.Run(fmt.Sprintf("%s/n%d/%s", a.Name(), size, op), func(b *testing.B) {
					target := token
					if op == "miss" {
						target = referenceMD5(a, plain+"wrong", salt)
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
							md5BenchmarkString = got
						} else {
							got, err := a.Recover(target, salt, plain)
							if op == "miss" {
								if err != types.ErrVerificationFailed || got != "" {
									b.Fatal("invalid miss")
								}
							} else if err != nil || got != plain {
								b.Fatal("invalid hit")
							}
							md5BenchmarkString = got
						}
					}
				})
			}
		}
	}
}

// 相同输入比较连续摘要和分段写入；不含 token 编码/比较开销。
func BenchmarkMD5DigestMethods(b *testing.B) {
	for _, size := range []int{8, 64, 4096} {
		plain, salt := strings.Repeat("p", size), "0123456789abcdef"
		want := stdmd5.Sum([]byte(salt + plain))
		for _, method := range []string{"sum", "split"} {
			b.Run(fmt.Sprintf("n%d/%s", size, method), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					var got [stdmd5.Size]byte
					if method == "sum" {
						got = stdmd5.Sum([]byte(salt + plain))
					} else {
						h := stdmd5.New()
						h.Write([]byte(salt))
						h.Write([]byte(plain))
						h.Sum(got[:0])
					}
					if got != want {
						b.Fatal("invalid digest")
					}
					md5BenchmarkDigest = got
				}
			})
		}
	}
}
