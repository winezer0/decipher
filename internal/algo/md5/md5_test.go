package md5

import (
	"testing"

	"github.com/winezer0/decipher/internal/algo/types"
)

func TestMD5(t *testing.T) {
	algo := &MD5Algo{}

	tests := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"basic_no_salt", "123456", "", "e10adc3949ba59abbe56e057f20f883e"},
		{"with_salt", "123456", "salt", "e10adc3949ba59abbe56e057f20f883e"},
		{"empty", "", "", "d41d8cd98f00b204e9800998ecf8427e"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := algo.Seal(tt.plaintext, tt.salt)
			if err != nil {
				t.Errorf("MD5Algo.Seal() error = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("MD5Algo.Seal(%q, %q) = %q; want %q", tt.plaintext, tt.salt, got, tt.want)
			}
		})
	}
}

func TestMD5Algo_GetAlgoType(t *testing.T) {
	algo := &MD5Algo{}
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("MD5Algo.GetAlgoType() = %v; want %v", got, types.AlgoIsStatic)
	}
}

func TestMD5Algo_Recover(t *testing.T) {
	algo := &MD5Algo{}

	tests := []struct {
		name           string
		plaintext      string
		salt           string
		candidatePlain string
		wantMatch      bool
	}{
		{"match_no_salt", "123456", "", "123456", true},
		{"no_match_no_salt", "123456", "", "wrong", false},
		{"match_with_salt", "123456", "salt", "123456", true},
		{"no_match_wrong_salt", "123456", "salt", "wrong", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, _ := algo.Seal(tt.plaintext, tt.salt)
			got, err := algo.Recover(token, tt.salt, tt.candidatePlain)

			if tt.wantMatch {
				if err != nil {
					t.Errorf("MD5Algo.Recover() error = %v, want nil", err)
					return
				}
				if got != tt.candidatePlain {
					t.Errorf("MD5Algo.Recover() = %q; want %q", got, tt.candidatePlain)
				}
			} else {
				if err != types.ErrVerificationFailed {
					t.Errorf("MD5Algo.Recover() error = %v; want ErrVerificationFailed", err)
				}
			}
		})
	}
}
