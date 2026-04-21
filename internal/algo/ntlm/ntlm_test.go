package ntlm

import (
	"testing"
)

func TestNTLMAlgo_Seal(t *testing.T) {
	algo := &NTLMAlgo{}
	testCases := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"123456", "123456", "", "32ed87bdb5fdc5e9cba88547376818d4"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := algo.Seal(tc.plaintext, tc.salt)
			if err != nil {
				t.Errorf("NTLMAlgo.Seal() error = %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("NTLMAlgo.Seal() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNTLMAlgo_Recover(t *testing.T) {
	algo := &NTLMAlgo{}

	// Test with correct plaintext
	plaintext := "123456"
	expectedHash := "32ed87bdb5fdc5e9cba88547376818d4"
	got, err := algo.Recover(expectedHash, "", plaintext)
	if err != nil {
		t.Errorf("NTLMAlgo.Recover() error = %v", err)
		return
	}
	if got != plaintext {
		t.Errorf("NTLMAlgo.Recover() = %v, want %v", got, plaintext)
	}

	// Test with wrong candidate
	wrongPlaintext := "wrong123"
	_, err = algo.Recover(expectedHash, "", wrongPlaintext)
	if err == nil {
		t.Errorf("NTLMAlgo.Recover() with wrong candidate should return error")
	}
}
