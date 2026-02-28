package sha

import (
	"decipher/internal/algo/types"
	"testing"
)

func TestSHA1Algo_Name(t *testing.T) {
	algo := &SHA1Algo{}
	if got := algo.Name(); got != "sha1" {
		t.Errorf("SHA1Algo.Name() = %v, want sha1", got)
	}
}

func TestSHA1Algo_GetAlgoType(t *testing.T) {
	algo := &SHA1Algo{}
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("SHA1Algo.GetAlgoType() = %v, want %v", got, types.AlgoIsStatic)
	}
}

func TestSHA1Algo_NeedsPrecomputation(t *testing.T) {
	algo := &SHA1Algo{}
	if got := algo.NeedsPrecomputation(); got != true {
		t.Errorf("SHA1Algo.NeedsPrecomputation() = %v, want true", got)
	}
}

func TestSHA1Algo_Seal(t *testing.T) {
	algo := &SHA1Algo{}
	tests := []struct {
		plaintext string
		want      string
	}{
		{"123456", "7c4a8d09ca3762af61e59520943dc26494f8941b"},
		{"password", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"},
		{"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
	}

	for _, tt := range tests {
		t.Run(tt.plaintext, func(t *testing.T) {
			got, err := algo.Seal(tt.plaintext, "")
			if err != nil {
				t.Errorf("SHA1Algo.Seal() error = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("SHA1Algo.Seal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSHA1Algo_Recover(t *testing.T) {
	algo := &SHA1Algo{}

	t.Run("success", func(t *testing.T) {
		token := "7c4a8d09ca3762af61e59520943dc26494f8941b"
		got, err := algo.Recover(token, "", "123456")
		if err != nil {
			t.Errorf("SHA1Algo.Recover() error = %v", err)
			return
		}
		if got != "123456" {
			t.Errorf("SHA1Algo.Recover() = %v, want 123456", got)
		}
	})

	t.Run("failure", func(t *testing.T) {
		token := "7c4a8d09ca3762af61e59520943dc26494f8941b"
		_, err := algo.Recover(token, "", "wrong")
		if err != types.ErrVerificationFailed {
			t.Errorf("SHA1Algo.Recover() error = %v, want ErrVerificationFailed", err)
		}
	})
}
