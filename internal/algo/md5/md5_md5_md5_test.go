package md5

import (
	"testing"

	"github.com/winezer0/decipher/internal/algo/types"
)

func TestMD5TripleAlgo_GetAlgoType(t *testing.T) {
	algo := &MD5TripleAlgo{}
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("MD5TripleAlgo.GetAlgoType() = %v, want AlgoIsStatic", got)
	}
}

func TestMD5TripleAlgo_NeedAddToPredb(t *testing.T) {
	algo := &MD5TripleAlgo{}
	if got := algo.NeedAddToPredb(); !got {
		t.Errorf("MD5TripleAlgo.NeedAddToPredb() = %v, want true", got)
	}
}

func TestMD5TripleAlgo_Seal(t *testing.T) {
	algo := &MD5TripleAlgo{}
	testCases := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"123456", "123456", "", "c56d0e9a7ccec67b4ea131655038d604"},
		{"empty", "", "", "acf7ef943fdeb3cbfed8dd0d8f584731"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := algo.Seal(tc.plaintext, tc.salt)
			if err != nil {
				t.Errorf("MD5TripleAlgo.Seal() error = %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("MD5TripleAlgo.Seal(%q, %q) = %q, want %q", tc.plaintext, tc.salt, got, tc.want)
			}
		})
	}
}

func TestMD5TripleAlgo_Recover(t *testing.T) {
	algo := &MD5TripleAlgo{}
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
					t.Errorf("MD5TripleAlgo.Recover() error = %v, want ErrVerificationFailed", err)
				}
				if got != "" {
					t.Errorf("MD5TripleAlgo.Recover() = %q, want 空字符串", got)
				}
			} else {
				if err != nil {
					t.Errorf("MD5TripleAlgo.Recover() error = %v, want nil", err)
					return
				}
				if got != tc.expected {
					t.Errorf("MD5TripleAlgo.Recover() = %q, want %q", got, tc.expected)
				}
			}
		})
	}
}
