package base64

import (
	"testing"

	"github.com/winezer0/decipher/internal/algo/types"
)

func TestBase64Algo(t *testing.T) {
	tests := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"basic", "123456", "", "MTIzNDU2"},
		{"empty", "", "", ""},
		{"with_salt", "123456", "ignored", "MTIzNDU2"},
	}

	algo := &Base64Algo{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := algo.Seal(tt.plaintext, tt.salt)
			if err != nil {
				t.Errorf("Base64Algo.Seal() error = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("Base64Algo.Seal(%q, %q) = %q, want %q", tt.plaintext, tt.salt, got, tt.want)
			}
		})
	}
}

func TestBase64Algo_GetAlgoType(t *testing.T) {
	algo := &Base64Algo{}
	if got := algo.GetAlgoType(); got != types.AlgoIsEncrypt {
		t.Errorf("Base64Algo.GetAlgoType() = %v; want %v", got, types.AlgoIsEncrypt)
	}
}

func TestBase64Algo_Recover(t *testing.T) {
	algo := &Base64Algo{}

	tests := []struct {
		name      string
		plaintext string
		want      string
	}{
		{"basic", "MTIzNDU2", "123456"},
		{"empty", "", ""},
		{"with_padding", "SGVsbG8gV29ybGQ=", "Hello World"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := algo.Recover(tt.plaintext, "", "")

			if err != nil {
				t.Errorf("Base64Algo.Recover() error = %v, want nil", err)
				return
			}
			if got != tt.want {
				t.Errorf("Base64Algo.Recover() = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestBase64Algo_Recover_Invalid(t *testing.T) {
	algo := &Base64Algo{}

	tests := []struct {
		name  string
		token string
	}{
		{"invalid_base64", "!!!invalid!!!"},
		{"not_base64", "not@base64#"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := algo.Recover(tt.token, "", "")
			if err != types.ErrDecryptionFailed {
				t.Errorf("Base64Algo.Recover() error = %v; want ErrDecryptionFailed", err)
			}
		})
	}
}
