package md5

import (
	"decipher/internal/algo/types"
	"testing"
)

func TestMD5UnicodeAlgo(t *testing.T) {
	algo := &MD5UnicodeAlgo{}

	// Test Name
	if got := algo.Name(); got != "md5(unicode($pass))" {
		t.Errorf("Name() = %q; want %q", got, "md5(unicode($pass))")
	}

	// Test GetAlgoType
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("GetAlgoType() = %v; want %v", got, types.AlgoIsStatic)
	}

	// Test NeedAddToPredb
	if got := algo.NeedAddToPredb(); got != true {
		t.Errorf("NeedAddToPredb() = %v; want %v", got, true)
	}

	// Test Seal with specific hash values
	testCases := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"123456", "123456", "", "ce0bfd15059b68d67688884d7a3d3e8c"},
		{"empty", "", "", "d41d8cd98f00b204e9800998ecf8427e"},
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
	expectedHash := "ce0bfd15059b68d67688884d7a3d3e8c"
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
