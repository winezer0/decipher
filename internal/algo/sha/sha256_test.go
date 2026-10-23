package sha

import (
	"github.com/winezer0/decipher/internal/algo/types"
	"testing"
)

func TestSHA256Algo_GetAlgoType(t *testing.T) {
	algo := &SHA256Algo{}
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("SHA256Algo.GetAlgoType() = %v, want %v", got, types.AlgoIsStatic)
	}
}

func TestSHA256Algo_NeedAddToPredb(t *testing.T) {
	algo := &SHA256Algo{}
	if got := algo.NeedAddToPredb(); got != true {
		t.Errorf("SHA256Algo.NeedAddToPredb() = %v, want true", got)
	}
}

func TestSHA256Algo_Seal(t *testing.T) {
	algo := &SHA256Algo{}
	tests := []struct {
		plaintext string
		want      string
	}{
		{"123456", "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"},
		{"password", "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"},
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	}

	for _, tt := range tests {
		t.Run(tt.plaintext, func(t *testing.T) {
			got, err := algo.Seal(tt.plaintext, "")
			if err != nil {
				t.Errorf("SHA256Algo.Seal() error = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("SHA256Algo.Seal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSHA256Algo_Recover(t *testing.T) {
	algo := &SHA256Algo{}

	t.Run("success", func(t *testing.T) {
		token := "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
		got, err := algo.Recover(token, "", "123456")
		if err != nil {
			t.Errorf("SHA256Algo.Recover() error = %v", err)
			return
		}
		if got != "123456" {
			t.Errorf("SHA256Algo.Recover() = %v, want 123456", got)
		}
	})

	t.Run("failure", func(t *testing.T) {
		token := "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
		_, err := algo.Recover(token, "", "wrong")
		if err != types.ErrVerificationFailed {
			t.Errorf("SHA256Algo.Recover() error = %v, want ErrVerificationFailed", err)
		}
	})
}
