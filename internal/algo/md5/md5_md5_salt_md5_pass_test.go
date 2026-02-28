package md5

import (
	"decipher/internal/algo/types"
	"testing"
)

func TestMD5MD5SaltMD5PassAlgo(t *testing.T) {
	algo := &MD5MD5SaltMD5PassAlgo{}

	// Test Name
	if got := algo.Name(); got != "md5(md5($salt).md5($pass))" {
		t.Errorf("Name() = %q; want %q", got, "md5(md5($salt).md5($pass))")
	}

	// Test GetAlgoType
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("GetAlgoType() = %v; want %v", got, types.AlgoIsStatic)
	}

	// Test NeedsPrecomputation
	if got := algo.NeedsPrecomputation(); got != true {
		t.Errorf("NeedsPrecomputation() = %v; want %v", got, true)
	}

	// Test with user-provided test data
	plaintext := "123456"
	secret := "66666"
	expectedEncrypted := "36de57bed0407ca1a83ae203850dc6a7"

	// Test Seal
	sealed, err := algo.Seal(plaintext, secret)
	if err != nil {
		t.Errorf("Seal() error = %v; want nil", err)
	}
	if sealed != expectedEncrypted {
		t.Errorf("Seal() = %q; want %q", sealed, expectedEncrypted)
	}

	// Test Recover with correct plaintext
	recovered, err := algo.Recover(expectedEncrypted, secret, plaintext)
	if err != nil {
		t.Errorf("Recover() error = %v; want nil", err)
	}
	if recovered != plaintext {
		t.Errorf("Recover() = %q; want %q", recovered, plaintext)
	}

	// Test Recover with wrong candidate
	wrongPlaintext := "wrong123"
	_, err = algo.Recover(expectedEncrypted, secret, wrongPlaintext)
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
