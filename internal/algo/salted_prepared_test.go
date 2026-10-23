package algo_test

import (
	"decipher/internal/algo"
	"decipher/internal/algo/types"
	"fmt"
	"strings"
	"testing"
)

func saltedAlgorithms() []algo.Algorithm {
	var selected []algo.Algorithm
	for _, a := range digestAlgorithms {
		if a.NeedSalt() {
			selected = append(selected, a)
		}
	}
	return selected
}

func checkSaltedPrepared(t *testing.T, a algo.Algorithm, plain, salt string) {
	t.Helper()
	recover, _ := algo.PrepareRecover(a)
	token := digestReference(a, plain, salt)
	for _, token := range []string{token, strings.ToUpper(token)} {
		target := algo.DecodeDigest(token)
		original := target
		for _, candidate := range []string{plain + "wrong", plain, plain + "wrong", plain} {
			got, err := recover(&target, salt, candidate)
			want, wantErr := a.Recover(token, salt, candidate)
			if got != want || err != wantErr {
				t.Fatalf("%s lengths %d/%d: got %q %v want %q %v", a.Name(), len(plain), len(salt), got, err, want, wantErr)
			}
			if candidate == plain {
				if got != plain || err != nil {
					t.Fatal("reference digest rejected")
				}
			} else if got != "" || err != types.ErrVerificationFailed {
				t.Fatal("wrong candidate accepted")
			}
		}
		if target != original {
			t.Fatal("shared digest mutated")
		}
	}
}

func TestSaltedPreparedBoundaries(t *testing.T) {
	for _, a := range saltedAlgorithms() {
		t.Run(a.Name(), func(t *testing.T) {
			for _, size := range []int{0, 1, 31, 32, 33, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 255, 256, 257, 4096} {
				splits := map[int]bool{0: true, size / 2: true, size: true}
				if size > 0 {
					splits[1] = true
					splits[size-1] = true
				}
				if size == 256 || size == 257 {
					for split := 0; split <= size; split++ {
						splits[split] = true
					}
				}
				for split := range splits {
					plain, salt := make([]byte, size-split), make([]byte, split)
					for i := range plain {
						plain[i] = byte(i*37 + 17)
					}
					for i := range salt {
						salt[i] = byte(i*43 + 7)
					}
					checkSaltedPrepared(t, a, string(plain), string(salt))
				}
			}
		})
	}
}

func TestSaltedPreparedShortInputAllocations(t *testing.T) {
	for _, a := range saltedAlgorithms() {
		recover, _ := algo.PrepareRecover(a)
		for _, size := range []int{0, 1, 31, 32, 33, 64, 128, 256} {
			plain, salt := strings.Repeat("p", size/2), strings.Repeat("s", size-size/2)
			target := algo.DecodeDigest(digestReference(a, plain, salt))
			var got string
			var err error
			allocations := testing.AllocsPerRun(100, func() { got, err = recover(&target, salt, plain) })
			if got != plain || err != nil {
				t.Fatal("digest mismatch")
			}
			if allocations != 0 {
				t.Fatalf("%s total=%d allocated %g times", a.Name(), size, allocations)
			}
		}
	}
}

func FuzzSaltedPreparedEquivalent(f *testing.F) {
	for _, pair := range [][2]string{{"", ""}, {"plain", "salt"}, {"中文🙂\x00", "盐\x00"}, {strings.Repeat("p", 128), strings.Repeat("s", 128)}, {strings.Repeat("p", 129), strings.Repeat("s", 128)}, {string([]byte{0xff, 0, 0x80}), string([]byte{0xfe, 0})}} {
		f.Add(pair[0], pair[1])
	}
	f.Fuzz(func(t *testing.T, plain, salt string) {
		if len(plain) > 65536 || len(salt) > 65536 {
			t.Skip()
		}
		for _, a := range saltedAlgorithms() {
			checkSaltedPrepared(t, a, plain, salt)
		}
	})
}

func BenchmarkSaltedPreparedBoundary(b *testing.B) {
	for _, a := range saltedAlgorithms() {
		recover, _ := algo.PrepareRecover(a)
		for _, size := range []int{24, 33, 64, 65, 128, 129, 256, 257, 4096} {
			plain, salt := strings.Repeat("p", size-16), strings.Repeat("s", 16)
			target := algo.DecodeDigest(digestReference(a, plain, salt))
			b.Run(fmt.Sprintf("%s/n%d", a.Name(), size), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					got, err := recover(&target, salt, plain)
					if got != plain || err != nil {
						b.Fatal("digest mismatch")
					}
					preparedResultSink = got
				}
			})
		}
	}
}
