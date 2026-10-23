package md5

import (
	"github.com/winezer0/decipher/internal/algo/types"
	"testing"
)

func TestMD5PassMD5SaltHexAlgo(t *testing.T) {
	algo := &MD5PassMD5SaltHexAlgo{}

	// Test Name
	if got := algo.Name(); got != "md5($pass.md5($salt))_hex" {
		t.Errorf("Name() = %q; want %q", got, "md5($pass.md5($salt))_hex")
	}

	// Test GetAlgoType
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("GetAlgoType() = %v; want %v", got, types.AlgoIsStatic)
	}

	// Test Seal and Recover with non-empty plaintext and secret
	plaintext := "123456"
	secret := "66666"
	expected := "046ec44e4e8cc8cb25198ab13a50e2b8"
	sealed, err := algo.Seal(plaintext, secret)
	if err != nil {
		t.Errorf("Seal() error = %v; want nil", err)
	}
	if sealed != expected {
		t.Errorf("Seal() = %q; want %q", sealed, expected)
	}

	recovered, err := algo.Recover(sealed, secret, plaintext)
	if err != nil {
		t.Errorf("Recover() error = %v; want nil", err)
	}
	if recovered != plaintext {
		t.Errorf("Recover() = %q; want %q", recovered, plaintext)
	}

	// Test Recover with wrong candidate
	wrongPlaintext := "wrong123"
	_, err = algo.Recover(sealed, secret, wrongPlaintext)
	if err == nil {
		t.Errorf("Recover() with wrong candidate should return error")
	}
}
