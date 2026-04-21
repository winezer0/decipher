package sha

import (
	"testing"

	"decipher/internal/algo/types"
)

func TestSHA256ShiroAlgo_GetAlgoType(t *testing.T) {
	algo := &SHA256ShiroAlgo{}
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("SHA256ShiroAlgo.GetAlgoType() = %v, want AlgoIsStatic", got)
	}
}

func TestSHA256ShiroAlgo_Seal(t *testing.T) {
	algo := &SHA256ShiroAlgo{}
	testCases := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"123456", "123456", "", "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"},
		{"empty", "", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := algo.Seal(tc.plaintext, tc.salt)
			if err != nil {
				t.Errorf("SHA256ShiroAlgo.Seal() error = %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("SHA256ShiroAlgo.Seal(%q, %q) = %q, want %q", tc.plaintext, tc.salt, got, tc.want)
			}
		})
	}
}

func TestSHA256ShiroAlgo_Recover(t *testing.T) {
	algo := &SHA256ShiroAlgo{}
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
					t.Errorf("SHA256ShiroAlgo.Recover() error = %v, want ErrVerificationFailed", err)
				}
				if got != "" {
					t.Errorf("SHA256ShiroAlgo.Recover() = %q, want 空字符串", got)
				}
			} else {
				if err != nil {
					t.Errorf("SHA256ShiroAlgo.Recover() error = %v, want nil", err)
					return
				}
				if got != tc.expected {
					t.Errorf("SHA256ShiroAlgo.Recover() = %q, want %q", got, tc.expected)
				}
			}
		})
	}
}
