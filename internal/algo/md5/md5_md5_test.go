package md5

import (
	"testing"

	"decipher/internal/algo/types"
)

func TestMD5DoubleAlgo_GetAlgoType(t *testing.T) {
	algo := &MD5DoubleAlgo{}
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("MD5DoubleAlgo.GetAlgoType() = %v, want AlgoIsStatic", got)
	}
}

func TestMD5DoubleAlgo_NeedAddToPredb(t *testing.T) {
	algo := &MD5DoubleAlgo{}
	if got := algo.NeedAddToPredb(); !got {
		t.Errorf("MD5DoubleAlgo.NeedAddToPredb() = %v, want true", got)
	}
}

func TestMD5DoubleAlgo_Seal(t *testing.T) {
	algo := &MD5DoubleAlgo{}
	testCases := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"123456", "123456", "", "14e1b600b1fd579f47433b88e8d85291"},
		{"empty", "", "", "74be16979710d4c4e7c6647856088456"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := algo.Seal(tc.plaintext, tc.salt)
			if err != nil {
				t.Errorf("MD5DoubleAlgo.Seal() error = %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("MD5DoubleAlgo.Seal(%q, %q) = %q, want %q", tc.plaintext, tc.salt, got, tc.want)
			}
		})
	}
}

func TestMD5DoubleAlgo_Recover(t *testing.T) {
	algo := &MD5DoubleAlgo{}
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
					t.Errorf("MD5DoubleAlgo.Recover() error = %v, want ErrVerificationFailed", err)
				}
				if got != "" {
					t.Errorf("MD5DoubleAlgo.Recover() = %q, want 空字符串", got)
				}
			} else {
				if err != nil {
					t.Errorf("MD5DoubleAlgo.Recover() error = %v, want nil", err)
					return
				}
				if got != tc.expected {
					t.Errorf("MD5DoubleAlgo.Recover() = %q, want %q", got, tc.expected)
				}
			}
		})
	}
}
