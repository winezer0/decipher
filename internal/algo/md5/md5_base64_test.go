package md5

import (
	"decipher/internal/algo/types"
	"testing"
)

func TestMD5Base64Algo(t *testing.T) {
	algo := &MD5Base64Algo{}

	// Test Name
	if got := algo.Name(); got != "base64(md5($pass))" {
		t.Errorf("Name() = %q; want %q", got, "base64(md5($pass))")
	}

	// Test GetAlgoType
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("GetAlgoType() = %v; want %v", got, types.AlgoIsStatic)
	}

	// Test Seal with specific hash values
	testCases := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"123456", "123456", "", "4QrcOUm6Wau+VuBX8g+IPg=="},
		{"empty", "", "", "1B2M2Y8AsgTpgAmY7PhCfg=="},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := algo.Seal(tc.plaintext, tc.salt)
			if err != nil {
				t.Errorf("Seal() error = %v; want nil", err)
				return
			}
			if got != tc.want {
				t.Errorf("Seal() = %q; want %q", got, tc.want)
			}
		})
	}

	// Test Recover with correct plaintext
	plaintext := "123456"
	expectedHash := "4QrcOUm6Wau+VuBX8g+IPg=="
	recovered, err := algo.Recover(expectedHash, "", plaintext)
	if err != nil {
		t.Errorf("Recover() error = %v; want nil", err)
	}
	if recovered != plaintext {
		t.Errorf("Recover() = %q; want %q", recovered, plaintext)
	}

	// Test Recover with wrong candidate
	wrongPlaintext := "wrong123"
	_, err = algo.Recover(expectedHash, "", wrongPlaintext)
	if err == nil {
		t.Errorf("Recover() with wrong candidate should return error")
	}
}
