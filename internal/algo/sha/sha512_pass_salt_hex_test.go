package sha

import (
	"decipher/internal/algo/types"
	"testing"
)

func TestSHA512PassSaltHexAlgo(t *testing.T) {
	algo := &SHA512PassSaltHexAlgo{}

	// Test Name
	if got := algo.Name(); got != "sha512($pass.$salt)_hex" {
		t.Errorf("Name() = %q; want %q", got, "sha512($pass.$salt)_hex")
	}

	// Test GetAlgoType
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("GetAlgoType() = %v; want %v", got, types.AlgoIsStatic)
	}

	// Test Seal and Recover with non-empty plaintext and secret
	plaintext := "123456"
	secret := "66666"
	expected := "385411ebd18e63325a78f999e6a8ed6b4e4c09bfcc626e23b8df9a068edd90a7450131fbc91eededffe05200d61f674b08b95718e447c92bd2d8fceaf80554ca"
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
