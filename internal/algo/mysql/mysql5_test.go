package mysql

import (
	"testing"

	"decipher/internal/algo/types"
)

func TestMySQL5Algo_Name(t *testing.T) {
	algo := &MySQL5Algo{}
	if got := algo.Name(); got != "mysql5" {
		t.Errorf("MySQL5Algo.Name() = %v, want mysql5", got)
	}
}

func TestMySQL5Algo_GetAlgoType(t *testing.T) {
	algo := &MySQL5Algo{}
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("MySQL5Algo.GetAlgoType() = %v, want AlgoIsStatic", got)
	}
}

func TestMySQL5Algo_NeedAddToPredb(t *testing.T) {
	algo := &MySQL5Algo{}
	if got := algo.NeedAddToPredb(); !got {
		t.Errorf("MySQL5Algo.NeedAddToPredb() = %v, want true", got)
	}
}

func TestMySQL5Algo_Seal(t *testing.T) {
	algo := &MySQL5Algo{}
	testCases := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"123456", "123456", "", "6bb4837eb74329105ee4568dda7dc67ed2ca2ad9"},
		{"empty", "", "", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := algo.Seal(tc.plaintext, tc.salt)
			if err != nil {
				t.Errorf("MySQL5Algo.Seal() error = %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("MySQL5Algo.Seal(%q, %q) = %q, want %q", tc.plaintext, tc.salt, got, tc.want)
			}
		})
	}
}

func TestMySQL5Algo_Recover(t *testing.T) {
	algo := &MySQL5Algo{}
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
					t.Errorf("MySQL5Algo.Recover() error = %v, want ErrVerificationFailed", err)
				}
				if got != "" {
					t.Errorf("MySQL5Algo.Recover() = %q, want 空字符串", got)
				}
			} else {
				if err != nil {
					t.Errorf("MySQL5Algo.Recover() error = %v, want nil", err)
					return
				}
				if got != tc.expected {
					t.Errorf("MySQL5Algo.Recover() = %q, want %q", got, tc.expected)
				}
			}
		})
	}
}
