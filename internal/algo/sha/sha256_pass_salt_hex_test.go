package sha

import (
	"decipher/internal/algo/types"
	"testing"
)

func TestSHA256PassSaltHexAlgo(t *testing.T) {
	algo := &SHA256PassSaltHexAlgo{}

	// Test Name
	if got := algo.Name(); got != "sha256($pass.$salt)_hex" {
		t.Errorf("Name() = %q; want %q", got, "sha256($pass.$salt)_hex")
	}

	// Test GetAlgoType
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("GetAlgoType() = %v; want %v", got, types.AlgoIsStatic)
	}

	// Test NeedsPrecomputation
	if got := algo.NeedsPrecomputation(); got != true {
		t.Errorf("NeedsPrecomputation() = %v; want %v", got, true)
	}

	// Test Seal and Recover with non-empty plaintext and secret
	plaintext := "123456"
	secret := "66666"
	expected := "d0eec2347309dc687be910836167ae0b87aae89caa03963604690ff3200a191b"
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
