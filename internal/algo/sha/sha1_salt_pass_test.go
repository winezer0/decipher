package sha

import (
	"github.com/winezer0/decipher/internal/algo/types"
	"testing"
)

func TestSHA1SaltPassAlgo_Seal(t *testing.T) {
	algo := &SHA1SaltPassAlgo{}
	tests := []struct {
		plaintext string
		salt      string
		expected  string
	}{
		{"123456", "66666", "f822afa7d1868b546eb832fe021b2aad9b85b6a4"},
	}

	for _, tt := range tests {
		t.Run(tt.plaintext+"_"+tt.salt, func(t *testing.T) {
			got, err := algo.Seal(tt.plaintext, tt.salt)
			if err != nil {
				t.Errorf("SHA1SaltPassAlgo.Seal() error = %v", err)
				return
			}
			if got != tt.expected {
				t.Errorf("SHA1SaltPassAlgo.Seal() = %v, want %v", got, tt.expected)
			}
			got2, err := algo.Seal(tt.plaintext, tt.salt)
			if err != nil {
				t.Errorf("SHA1SaltPassAlgo.Seal() error = %v", err)
				return
			}
			if got != got2 {
				t.Errorf("SHA1SaltPassAlgo.Seal() not deterministic")
			}
		})
	}
}

func TestSHA1SaltPassAlgo_Recover(t *testing.T) {
	algo := &SHA1SaltPassAlgo{}

	t.Run("success", func(t *testing.T) {
		token := "f822afa7d1868b546eb832fe021b2aad9b85b6a4"
		got, err := algo.Recover(token, "66666", "123456")
		if err != nil {
			t.Errorf("SHA1SaltPassAlgo.Recover() error = %v", err)
			return
		}
		if got != "123456" {
			t.Errorf("SHA1SaltPassAlgo.Recover() = %v, want 123456", got)
		}
	})

	t.Run("failure", func(t *testing.T) {
		token := "f822afa7d1868b546eb832fe021b2aad9b85b6a4"
		_, err := algo.Recover(token, "66666", "wrong")
		if err != types.ErrVerificationFailed {
			t.Errorf("SHA1SaltPassAlgo.Recover() error = %v, want ErrVerificationFailed", err)
		}
	})
}
