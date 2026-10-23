package sha

import (
	"testing"

	"github.com/winezer0/decipher/internal/algo/types"
)

func TestSHA1MD5Algo_GetAlgoType(t *testing.T) {
	algo := &SHA1MD5Algo{}
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("SHA1MD5Algo.GetAlgoType() = %v, want AlgoIsStatic", got)
	}
}

func TestSHA1MD5Algo_NeedAddToPredb(t *testing.T) {
	algo := &SHA1MD5Algo{}
	if got := algo.NeedAddToPredb(); !got {
		t.Errorf("SHA1MD5Algo.NeedAddToPredb() = %v, want true", got)
	}
}

func TestSHA1MD5Algo_Seal(t *testing.T) {
	algo := &SHA1MD5Algo{}
	testCases := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"123456", "123456", "", "10470c3b4b1fed12c3baac014be15fac67c6e815"},
		{"empty", "", "", "67a74306b06d0c01624fe0d0249a570f4d093747"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := algo.Seal(tc.plaintext, tc.salt)
			if err != nil {
				t.Errorf("SHA1MD5Algo.Seal() error = %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("SHA1MD5Algo.Seal(%q, %q) = %q, want %q", tc.plaintext, tc.salt, got, tc.want)
			}
		})
	}
}

func TestSHA1MD5Algo_Recover(t *testing.T) {
	algo := &SHA1MD5Algo{}
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
					t.Errorf("SHA1MD5Algo.Recover() error = %v, want ErrVerificationFailed", err)
				}
				if got != "" {
					t.Errorf("SHA1MD5Algo.Recover() = %q, want 空字符串", got)
				}
			} else {
				if err != nil {
					t.Errorf("SHA1MD5Algo.Recover() error = %v, want nil", err)
					return
				}
				if got != tc.expected {
					t.Errorf("SHA1MD5Algo.Recover() = %q, want %q", got, tc.expected)
				}
			}
		})
	}
}
