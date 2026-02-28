package sha

import (
	"testing"

	"decipher/internal/algo/types"
)

func TestSHA256SaltPassAlgo_Name(t *testing.T) {
	algo := &SHA256SaltPassAlgo{}
	if got := algo.Name(); got != "sha256($salt.$pass)" {
		t.Errorf("SHA256SaltPassAlgo.Name() = %v, want sha256($salt.$pass)", got)
	}
}

func TestSHA256SaltPassAlgo_GetAlgoType(t *testing.T) {
	algo := &SHA256SaltPassAlgo{}
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("SHA256SaltPassAlgo.GetAlgoType() = %v, want AlgoIsStatic", got)
	}
}

func TestSHA256SaltPassAlgo_NeedsPrecomputation(t *testing.T) {
	algo := &SHA256SaltPassAlgo{}
	if got := algo.NeedsPrecomputation(); !got {
		t.Errorf("SHA256SaltPassAlgo.NeedsPrecomputation() = %v, want true", got)
	}
}

func TestSHA256SaltPassAlgo_Seal(t *testing.T) {
	algo := &SHA256SaltPassAlgo{}
	testCases := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"123456_xxx", "123456", "xxx", "e6fa508c84fa5319cf6907933b93d83b0371805003758a015320328ec532128b"},
		{"empty", "", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := algo.Seal(tc.plaintext, tc.salt)
			if err != nil {
				t.Errorf("SHA256SaltPassAlgo.Seal() error = %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("SHA256SaltPassAlgo.Seal(%q, %q) = %q, want %q", tc.plaintext, tc.salt, got, tc.want)
			}
		})
	}
}

func TestSHA256SaltPassAlgo_Recover(t *testing.T) {
	algo := &SHA256SaltPassAlgo{}
	plaintext := "123456"
	salt := "xxx"
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
					t.Errorf("SHA256SaltPassAlgo.Recover() error = %v, want ErrVerificationFailed", err)
				}
				if got != "" {
					t.Errorf("SHA256SaltPassAlgo.Recover() = %q, want 空字符串", got)
				}
			} else {
				if err != nil {
					t.Errorf("SHA256SaltPassAlgo.Recover() error = %v, want nil", err)
					return
				}
				if got != tc.expected {
					t.Errorf("SHA256SaltPassAlgo.Recover() = %q, want %q", got, tc.expected)
				}
			}
		})
	}
}
