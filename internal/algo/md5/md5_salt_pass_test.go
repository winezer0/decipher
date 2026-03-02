package md5

import (
	"testing"

	"decipher/internal/algo/types"
)

func TestMD5SaltPassAlgo_Name(t *testing.T) {
	algo := &MD5SaltPassAlgo{}
	if got := algo.Name(); got != "md5($salt.$pass)" {
		t.Errorf("MD5SaltPassAlgo.Name() = %v, want md5($salt.$pass)", got)
	}
}

func TestMD5SaltPassAlgo_GetAlgoType(t *testing.T) {
	algo := &MD5SaltPassAlgo{}
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("MD5SaltPassAlgo.GetAlgoType() = %v, want AlgoIsStatic", got)
	}
}

func TestMD5SaltPassAlgo_NeedAddToPredb(t *testing.T) {
	algo := &MD5SaltPassAlgo{}
	if got := algo.NeedAddToPredb(); !got {
		t.Errorf("MD5SaltPassAlgo.NeedAddToPredb() = %v, want true", got)
	}
}

func TestMD5SaltPassAlgo_Seal(t *testing.T) {
	algo := &MD5SaltPassAlgo{}
	testCases := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"123456_xxx", "123456", "xxx", "5c18216aeb19c1a79f821902d846067b"},
		{"empty", "", "", "d41d8cd98f00b204e9800998ecf8427e"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := algo.Seal(tc.plaintext, tc.salt)
			if err != nil {
				t.Errorf("MD5SaltPassAlgo.Seal() error = %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("MD5SaltPassAlgo.Seal(%q, %q) = %q, want %q", tc.plaintext, tc.salt, got, tc.want)
			}
		})
	}
}

func TestMD5SaltPassAlgo_Recover(t *testing.T) {
	algo := &MD5SaltPassAlgo{}
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
					t.Errorf("MD5SaltPassAlgo.Recover() error = %v, want ErrVerificationFailed", err)
				}
				if got != "" {
					t.Errorf("MD5SaltPassAlgo.Recover() = %q, want 空字符串", got)
				}
			} else {
				if err != nil {
					t.Errorf("MD5SaltPassAlgo.Recover() error = %v, want nil", err)
					return
				}
				if got != tc.expected {
					t.Errorf("MD5SaltPassAlgo.Recover() = %q, want %q", got, tc.expected)
				}
			}
		})
	}
}
