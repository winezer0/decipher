package sha

import (
	"decipher/internal/algo/types"
	"testing"
)

func TestSHA512SaltPassAlgo(t *testing.T) {
	algo := &SHA512SaltPassAlgo{}

	// Test Name
	if got := algo.Name(); got != "sha512($salt.$pass)" {
		t.Errorf("Name() = %q; want %q", got, "sha512($salt.$pass)")
	}

	// Test GetAlgoType
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("GetAlgoType() = %v; want %v", got, types.AlgoIsStatic)
	}

	// Test NeedAddToPredb
	if got := algo.NeedAddToPredb(); got != true {
		t.Errorf("NeedAddToPredb() = %v; want %v", got, true)
	}

	// Test Seal and Recover with provided test data
	plaintext := "123456"
	secret := "66666"
	expectedHash := "9dc475221ca7255676c47d922f014f327726f0f67cd66b20b447004ca3cd24aafc0bff5eab3a9423d8cb53744922ca0b7d9a941fba4cc72144abb39b2a08c9a6"
	sealed, err := algo.Seal(plaintext, secret)
	if err != nil {
		t.Errorf("Seal() error = %v; want nil", err)
	}
	if sealed != expectedHash {
		t.Errorf("Seal() = %q; want %q", sealed, expectedHash)
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

	// Test Seal and Recover with empty string
	emptyPlaintext := ""
	emptySealed, err := algo.Seal(emptyPlaintext, secret)
	if err != nil {
		t.Errorf("Seal() with empty string error = %v; want nil", err)
	}

	emptyRecovered, err := algo.Recover(emptySealed, secret, emptyPlaintext)
	if err != nil {
		t.Errorf("Recover() with empty string error = %v; want nil", err)
	}
	if emptyRecovered != emptyPlaintext {
		t.Errorf("Recover() with empty string = %q; want %q", emptyRecovered, emptyPlaintext)
	}
}
