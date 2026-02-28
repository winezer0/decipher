package md5

import (
	"decipher/internal/algo/types"
	"testing"
)

func TestMD5SHA1Algo(t *testing.T) {
	algo := &MD5SHA1Algo{}

	// Test Name
	if got := algo.Name(); got != "md5(sha1($pass))" {
		t.Errorf("Name() = %q; want %q", got, "md5(sha1($pass))")
	}

	// Test GetAlgoType
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("GetAlgoType() = %v; want %v", got, types.AlgoIsStatic)
	}

	// Test NeedsPrecomputation
	if got := algo.NeedsPrecomputation(); got != true {
		t.Errorf("NeedsPrecomputation() = %v; want %v", got, true)
	}

	// Test Seal with specific hash values
	testCases := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"123456", "123456", "", "d93a5def7511da3d0f2d171d9c344e91"},
		{"empty", "", "", "0144712dd81be0c3d9724f5e56ce6685"},
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
	expectedHash := "d93a5def7511da3d0f2d171d9c344e91"
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
