package md5

import (
	"decipher/internal/algo/types"
	"testing"
)

func TestMD5BTAdminAlgo(t *testing.T) {
	algo := &MD5BTAdminAlgo{}

	// Test Name
	if got := algo.Name(); got != "md5_md5_md5_bt_admin" {
		t.Errorf("Name() = %q; want %q", got, "md5_md5_md5_bt_admin")
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
	plaintext := "aJEohvBvH8BD"
	secret := "1001V11000000033Z1AA"
	expectedEncrypted := "744acfc0c498c8dc2ee828cf46cba7f4"
	
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
