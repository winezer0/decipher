package sha

import (
	"decipher/internal/algo/types"
	"testing"
)

func TestSHA1PassSalt2Algo_Name(t *testing.T) {
	algo := &SHA1PassSalt2Algo{}
	if got := algo.Name(); got != "sha1($pass-$salt)" {
		t.Errorf("SHA1PassSalt2Algo.Name() = %v, want sha1($pass-$salt)", got)
	}
}

func TestSHA1PassSalt2Algo_Seal(t *testing.T) {
	algo := &SHA1PassSalt2Algo{}
	tests := []struct {
		plaintext string
		salt      string
		expected  string
	}{
		{"123456", "66666", "0abb150cae63aeec3449e431b9505666085d886e"},
	}

	for _, tt := range tests {
		t.Run(tt.plaintext+"_"+tt.salt, func(t *testing.T) {
			got, err := algo.Seal(tt.plaintext, tt.salt)
			if err != nil {
				t.Errorf("SHA1PassSalt2Algo.Seal() error = %v", err)
				return
			}
			if got != tt.expected {
				t.Errorf("SHA1PassSalt2Algo.Seal() = %v, want %v", got, tt.expected)
			}
			got2, err := algo.Seal(tt.plaintext, tt.salt)
			if err != nil {
				t.Errorf("SHA1PassSalt2Algo.Seal() error = %v", err)
				return
			}
			if got != got2 {
				t.Errorf("SHA1PassSalt2Algo.Seal() not deterministic")
			}
		})
	}
}

func TestSHA1PassSalt2Algo_Recover(t *testing.T) {
	algo := &SHA1PassSalt2Algo{}

	t.Run("success", func(t *testing.T) {
		token := "0abb150cae63aeec3449e431b9505666085d886e"
		got, err := algo.Recover(token, "66666", "123456")
		if err != nil {
			t.Errorf("SHA1PassSalt2Algo.Recover() error = %v", err)
			return
		}
		if got != "123456" {
			t.Errorf("SHA1PassSalt2Algo.Recover() = %v, want 123456", got)
		}
	})

	t.Run("failure", func(t *testing.T) {
		token := "dd45b52caddbe8a1b29a88ad04904168e1fb64f3"
		_, err := algo.Recover(token, "66666", "wrong")
		if err != types.ErrVerificationFailed {
			t.Errorf("SHA1PassSalt2Algo.Recover() error = %v, want ErrVerificationFailed", err)
		}
	})
}
