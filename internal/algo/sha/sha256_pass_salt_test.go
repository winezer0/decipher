package sha

import (
	"testing"

	"decipher/internal/algo/types"
)

func TestSHA256PassSaltAlgo_GetAlgoType(t *testing.T) {
	algo := &SHA256PassSaltAlgo{}
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("SHA256PassSaltAlgo.GetAlgoType() = %v, want AlgoIsStatic", got)
	}
}

func TestSHA256PassSaltAlgo_Seal(t *testing.T) {
	algo := &SHA256PassSaltAlgo{}
	testCases := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"123456_xxx", "123456", "xxx", "68aa0b7d238afa3c9fa4476d0226ce9a02b9912725961c4845dd2a41b740b075"},
		{"empty", "", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := algo.Seal(tc.plaintext, tc.salt)
			if err != nil {
				t.Errorf("SHA256PassSaltAlgo.Seal() error = %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("SHA256PassSaltAlgo.Seal(%q, %q) = %q, want %q", tc.plaintext, tc.salt, got, tc.want)
			}
		})
	}
}

func TestSHA256PassSaltAlgo_Recover(t *testing.T) {
	algo := &SHA256PassSaltAlgo{}
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
					t.Errorf("SHA256PassSaltAlgo.Recover() error = %v, want ErrVerificationFailed", err)
				}
				if got != "" {
					t.Errorf("SHA256PassSaltAlgo.Recover() = %q, want 空字符串", got)
				}
			} else {
				if err != nil {
					t.Errorf("SHA256PassSaltAlgo.Recover() error = %v, want nil", err)
					return
				}
				if got != tc.expected {
					t.Errorf("SHA256PassSaltAlgo.Recover() = %q, want %q", got, tc.expected)
				}
			}
		})
	}
}
