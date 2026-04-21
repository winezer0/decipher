package md5

import (
	"testing"

	"decipher/internal/algo/types"
)

func TestMD5PassMD5SaltAlgo_GetAlgoType(t *testing.T) {
	algo := &MD5PassMD5SaltAlgo{}
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("MD5PassMD5SaltAlgo.GetAlgoType() = %v, want AlgoIsStatic", got)
	}
}

func TestMD5PassMD5SaltAlgo_Seal(t *testing.T) {
	algo := &MD5PassMD5SaltAlgo{}
	testCases := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"123456_xxx", "123456", "xxx", "d19ea2d4fc2d37d339ec9a7313b1cb8b"},
		{"empty", "", "", "74be16979710d4c4e7c6647856088456"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := algo.Seal(tc.plaintext, tc.salt)
			if err != nil {
				t.Errorf("MD5PassMD5SaltAlgo.Seal() error = %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("MD5PassMD5SaltAlgo.Seal(%q, %q) = %q, want %q", tc.plaintext, tc.salt, got, tc.want)
			}
		})
	}
}

func TestMD5PassMD5SaltAlgo_Recover(t *testing.T) {
	algo := &MD5PassMD5SaltAlgo{}
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
					t.Errorf("MD5PassMD5SaltAlgo.Recover() error = %v, want ErrVerificationFailed", err)
				}
				if got != "" {
					t.Errorf("MD5PassMD5SaltAlgo.Recover() = %q, want 空字符串", got)
				}
			} else {
				if err != nil {
					t.Errorf("MD5PassMD5SaltAlgo.Recover() error = %v, want nil", err)
					return
				}
				if got != tc.expected {
					t.Errorf("MD5PassMD5SaltAlgo.Recover() = %q, want %q", got, tc.expected)
				}
			}
		})
	}
}
