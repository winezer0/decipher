package mysql

import (
	"testing"

	"decipher/internal/algo/types"
)

func TestMySQLPre41Algo_GetAlgoType(t *testing.T) {
	algo := &MySQLPre41Algo{}
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("MySQLPre41Algo.GetAlgoType() = %v, want AlgoIsStatic", got)
	}
}

func TestMySQLPre41Algo_Seal(t *testing.T) {
	algo := &MySQLPre41Algo{}
	testCases := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"123456", "123456", "", "565491d704013245"},
		{"empty", "", "", "d9e0ee97b8f27ce829e901b2e0d123a9"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := algo.Seal(tc.plaintext, tc.salt)
			if err != nil {
				t.Errorf("MySQLPre41Algo.Seal() error = %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("MySQLPre41Algo.Seal(%q, %q) = %q, want %q", tc.plaintext, tc.salt, got, tc.want)
			}
		})
	}
}

func TestMySQLPre41Algo_Recover(t *testing.T) {
	algo := &MySQLPre41Algo{}
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
					t.Errorf("MySQLPre41Algo.Recover() error = %v, want ErrVerificationFailed", err)
				}
				if got != "" {
					t.Errorf("MySQLPre41Algo.Recover() = %q, want 空字符串", got)
				}
			} else {
				if err != nil {
					t.Errorf("MySQLPre41Algo.Recover() error = %v, want nil", err)
					return
				}
				if got != tc.expected {
					t.Errorf("MySQLPre41Algo.Recover() = %q, want %q", got, tc.expected)
				}
			}
		})
	}
}
