package sha

import (
	"testing"

	"decipher/internal/algo/types"
)

func TestSHA1DoubleAlgo_Name(t *testing.T) {
	algo := &SHA1DoubleAlgo{}
	if got := algo.Name(); got != "sha1(sha1($pass))" {
		t.Errorf("SHA1DoubleAlgo.Name() = %v, want sha1(sha1($pass))", got)
	}
}

func TestSHA1DoubleAlgo_GetAlgoType(t *testing.T) {
	algo := &SHA1DoubleAlgo{}
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("SHA1DoubleAlgo.GetAlgoType() = %v, want AlgoIsStatic", got)
	}
}

func TestSHA1DoubleAlgo_NeedsPrecomputation(t *testing.T) {
	algo := &SHA1DoubleAlgo{}
	if got := algo.NeedsPrecomputation(); !got {
		t.Errorf("SHA1DoubleAlgo.NeedsPrecomputation() = %v, want true", got)
	}
}

func TestSHA1DoubleAlgo_Seal(t *testing.T) {
	algo := &SHA1DoubleAlgo{}
	testCases := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"123456", "123456", "", "69c5fcebaa65b560eaf06c3fbeb481ae44b8d618"},
		{"empty", "", "", "10a34637ad661d98ba3344717656fcc76209c2f8"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := algo.Seal(tc.plaintext, tc.salt)
			if err != nil {
				t.Errorf("SHA1DoubleAlgo.Seal() error = %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("SHA1DoubleAlgo.Seal(%q, %q) = %q, want %q", tc.plaintext, tc.salt, got, tc.want)
			}
		})
	}
}

func TestSHA1DoubleAlgo_Recover(t *testing.T) {
	algo := &SHA1DoubleAlgo{}
	plaintext := "123456"
	salt := ""
	token, _ := algo.Seal(plaintext, salt)

	testCases := []struct {
		name           string
		candidatePlain string
		expected       string
		expectedErr    bool
	}{
		{"success", plaintext, plaintext, false},
		{"failure", "wrong", "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := algo.Recover(token, salt, tc.candidatePlain)
			if tc.expectedErr {
				if err != types.ErrVerificationFailed {
					t.Errorf("SHA1DoubleAlgo.Recover() error = %v, want ErrVerificationFailed", err)
				}
				if got != "" {
					t.Errorf("SHA1DoubleAlgo.Recover() = %q, want 空字符串", got)
				}
			} else {
				if err != nil {
					t.Errorf("SHA1DoubleAlgo.Recover() error = %v, want nil", err)
					return
				}
				if got != tc.expected {
					t.Errorf("SHA1DoubleAlgo.Recover() = %q, want %q", got, tc.expected)
				}
			}
		})
	}
}
