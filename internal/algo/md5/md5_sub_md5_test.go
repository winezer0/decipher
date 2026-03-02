package md5

import (
	"decipher/internal/algo/types"
	"testing"
)

func TestMD5SubAlgo(t *testing.T) {
	algo := &MD5SubAlgo{}

	// Test Name
	if got := algo.Name(); got != "md5(substring(md5($pass),8,16))" {
		t.Errorf("Name() = %q; want %q", got, "md5(substring(md5($pass),8,16))")
	}

	// Test GetAlgoType
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("GetAlgoType() = %v; want %v", got, types.AlgoIsStatic)
	}

	// Test NeedAddToPredb
	if got := algo.NeedAddToPredb(); got != true {
		t.Errorf("NeedAddToPredb() = %v; want %v", got, true)
	}

	// Test with user-provided test data
	plaintext := "123456"
	expectedEncrypted := "3acf16259def65456fc2a68ab5e10d96"
	
	// Test Seal
	sealed, err := algo.Seal(plaintext, "")
	if err != nil {
		t.Errorf("Seal() error = %v; want nil", err)
	}
	if sealed != expectedEncrypted {
		t.Errorf("Seal() = %q; want %q", sealed, expectedEncrypted)
	}

	// Test Recover with correct plaintext
	recovered, err := algo.Recover(expectedEncrypted, "", plaintext)
	if err != nil {
		t.Errorf("Recover() error = %v; want nil", err)
	}
	if recovered != plaintext {
		t.Errorf("Recover() = %q; want %q", recovered, plaintext)
	}

	// Test Recover with wrong candidate
	wrongPlaintext := "wrong123"
	_, err = algo.Recover(expectedEncrypted, "", wrongPlaintext)
	if err == nil {
		t.Errorf("Recover() with wrong candidate should return error")
	}

	// Test Seal and Recover with empty string
	emptyPlaintext := ""
	emptySealed, err := algo.Seal(emptyPlaintext, "")
	if err != nil {
		t.Errorf("Seal() with empty string error = %v; want nil", err)
	}

	emptyRecovered, err := algo.Recover(emptySealed, "", emptyPlaintext)
	if err != nil {
		t.Errorf("Recover() with empty string error = %v; want nil", err)
	}
	if emptyRecovered != emptyPlaintext {
		t.Errorf("Recover() with empty string = %q; want %q", emptyRecovered, emptyPlaintext)
	}
}
