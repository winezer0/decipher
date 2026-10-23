package sha

import (
	"github.com/winezer0/decipher/internal/algo/types"
	"testing"
)

func TestSHA1PassSaltAlgo_Seal(t *testing.T) {
	algo := &SHA1PassSaltAlgo{}
	tests := []struct {
		plaintext string
		salt      string
		expected  string
	}{
		{"123456", "66666", "dd45b52caddbe8a1b29a88ad04904168e1fb64f3"},
	}

	for _, tt := range tests {
		t.Run(tt.plaintext+"_"+tt.salt, func(t *testing.T) {
			got, err := algo.Seal(tt.plaintext, tt.salt)
			if err != nil {
				t.Errorf("SHA1PassSaltAlgo.Seal() error = %v", err)
				return
			}
			if got != tt.expected {
				t.Errorf("SHA1PassSaltAlgo.Seal() = %v, want %v", got, tt.expected)
			}
			got2, err := algo.Seal(tt.plaintext, tt.salt)
			if err != nil {
				t.Errorf("SHA1PassSaltAlgo.Seal() error = %v", err)
				return
			}
			if got != got2 {
				t.Errorf("SHA1PassSaltAlgo.Seal() not deterministic")
			}
		})
	}
}

func TestSHA1PassSaltAlgo_Recover(t *testing.T) {
	algo := &SHA1PassSaltAlgo{}

	t.Run("success", func(t *testing.T) {
		token := "dd45b52caddbe8a1b29a88ad04904168e1fb64f3"
		got, err := algo.Recover(token, "66666", "123456")
		if err != nil {
			t.Errorf("SHA1PassSaltAlgo.Recover() error = %v", err)
			return
		}
		if got != "123456" {
			t.Errorf("SHA1PassSaltAlgo.Recover() = %v, want 123456", got)
		}
	})

	t.Run("failure", func(t *testing.T) {
		token := "dd45b52caddbe8a1b29a88ad04904168e1fb64f3"
		_, err := algo.Recover(token, "66666", "wrong")
		if err != types.ErrVerificationFailed {
			t.Errorf("SHA1PassSaltAlgo.Recover() error = %v, want ErrVerificationFailed", err)
		}
	})
}
