package md5

import (
	"testing"

	"decipher/internal/algo/types"
)

func TestMD5PassSaltAlgo_Name(t *testing.T) {
	algo := &MD5PassSaltAlgo{}
	if got := algo.Name(); got != "md5($pass.$salt)" {
		t.Errorf("MD5PassSaltAlgo.Name() = %v, want md5($pass.$salt)", got)
	}
}

func TestMD5PassSaltAlgo_GetAlgoType(t *testing.T) {
	algo := &MD5PassSaltAlgo{}
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("MD5PassSaltAlgo.GetAlgoType() = %v, want AlgoIsStatic", got)
	}
}

func TestMD5PassSaltAlgo_NeedsPrecomputation(t *testing.T) {
	algo := &MD5PassSaltAlgo{}
	if got := algo.NeedsPrecomputation(); !got {
		t.Errorf("MD5PassSaltAlgo.NeedsPrecomputation() = %v, want true", got)
	}
}

func TestMD5PassSaltAlgo_Seal(t *testing.T) {
	algo := &MD5PassSaltAlgo{}
	testCases := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"123456_xxx", "123456", "xxx", "e087dae60e744ea80722b785a75adbb7"},
		{"empty", "", "", "d41d8cd98f00b204e9800998ecf8427e"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := algo.Seal(tc.plaintext, tc.salt)
			if err != nil {
				t.Errorf("MD5PassSaltAlgo.Seal() error = %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("MD5PassSaltAlgo.Seal(%q, %q) = %q, want %q", tc.plaintext, tc.salt, got, tc.want)
			}
		})
	}
}

func TestMD5PassSaltAlgo_Recover(t *testing.T) {
	algo := &MD5PassSaltAlgo{}
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
					t.Errorf("MD5PassSaltAlgo.Recover() error = %v, want ErrVerificationFailed", err)
				}
				if got != "" {
					t.Errorf("MD5PassSaltAlgo.Recover() = %q, want 空字符串", got)
				}
			} else {
				if err != nil {
					t.Errorf("MD5PassSaltAlgo.Recover() error = %v, want nil", err)
					return
				}
				if got != tc.expected {
					t.Errorf("MD5PassSaltAlgo.Recover() = %q, want %q", got, tc.expected)
				}
			}
		})
	}
}
