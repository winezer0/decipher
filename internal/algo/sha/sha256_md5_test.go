package sha

import (
	"testing"

	"decipher/internal/algo/types"
)

func TestSHA256MD5Algo_Name(t *testing.T) {
	algo := &SHA256MD5Algo{}
	if got := algo.Name(); got != "sha256(md5($pass))" {
		t.Errorf("SHA256MD5Algo.Name() = %v, want sha256(md5($pass))", got)
	}
}

func TestSHA256MD5Algo_GetAlgoType(t *testing.T) {
	algo := &SHA256MD5Algo{}
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("SHA256MD5Algo.GetAlgoType() = %v, want AlgoIsStatic", got)
	}
}

func TestSHA256MD5Algo_NeedsPrecomputation(t *testing.T) {
	algo := &SHA256MD5Algo{}
	if got := algo.NeedsPrecomputation(); !got {
		t.Errorf("SHA256MD5Algo.NeedsPrecomputation() = %v, want true", got)
	}
}

func TestSHA256MD5Algo_Seal(t *testing.T) {
	algo := &SHA256MD5Algo{}
	testCases := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"123456", "123456", "", "cdf4a007e2b02a0c49fc9b7ccfbb8a10c644f635e1765dcf2a7ab794ddc7edac"},
		{"empty", "", "", "f215faf9d88b7f0a881632ee22459ee452a296c808d261b6cc993d3a1fd0600e"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := algo.Seal(tc.plaintext, tc.salt)
			if err != nil {
				t.Errorf("SHA256MD5Algo.Seal() error = %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("SHA256MD5Algo.Seal(%q, %q) = %q, want %q", tc.plaintext, tc.salt, got, tc.want)
			}
		})
	}
}

func TestSHA256MD5Algo_Recover(t *testing.T) {
	algo := &SHA256MD5Algo{}
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
					t.Errorf("SHA256MD5Algo.Recover() error = %v, want ErrVerificationFailed", err)
				}
				if got != "" {
					t.Errorf("SHA256MD5Algo.Recover() = %q, want 空字符串", got)
				}
			} else {
				if err != nil {
					t.Errorf("SHA256MD5Algo.Recover() error = %v, want nil", err)
					return
				}
				if got != tc.expected {
					t.Errorf("SHA256MD5Algo.Recover() = %q, want %q", got, tc.expected)
				}
			}
		})
	}
}
