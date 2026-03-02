package md5

import (
	"decipher/internal/algo/types"
	"testing"
)

func TestMD5MD5SaltMD5PassHexAlgo(t *testing.T) {
	algo := &MD5MD5SaltMD5PassHexAlgo{}

	// Test Name
	if got := algo.Name(); got != "md5(md5($salt).md5($pass))_hex" {
		t.Errorf("Name() = %q; want %q", got, "md5(md5($salt).md5($pass))_hex")
	}

	// Test GetAlgoType
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("GetAlgoType() = %v; want %v", got, types.AlgoIsStatic)
	}

	// Test NeedAddToPredb
	if got := algo.NeedAddToPredb(); got != true {
		t.Errorf("NeedAddToPredb() = %v; want %v", got, true)
	}

	// Test Seal and Recover with non-empty plaintext and secret
	plaintext := "123456"
	secret := "66666"
	expected := "c2058a78cb695dfcc1366aeb854c88ba"
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
