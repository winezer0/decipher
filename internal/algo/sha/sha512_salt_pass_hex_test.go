package sha

import (
	"github.com/winezer0/decipher/internal/algo/types"
	"testing"
)

func TestSHA512SaltPassHexAlgo(t *testing.T) {
	algo := &SHA512SaltPassHexAlgo{}

	// Test Name
	if got := algo.Name(); got != "sha512($salt.$pass)_hex" {
		t.Errorf("Name() = %q; want %q", got, "sha512($salt.$pass)_hex")
	}

	// Test GetAlgoType
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("GetAlgoType() = %v; want %v", got, types.AlgoIsStatic)
	}

	// Test Seal and Recover with non-empty plaintext and secret
	plaintext := "123456"
	secret := "66666"
	expected := "1fefddb440e405e08c93e36cb20fabb3f304aaed8fc959f149ac5e007293d29c159b67037e924794b1b1413a4f772172e8c1d84461a271f6d91385bc3353a87c"
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
