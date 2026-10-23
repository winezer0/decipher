package md5

import (
	"testing"

	"github.com/winezer0/decipher/internal/algo/types"
)

func TestMD5CustomLizhiAlgo_GetAlgoType(t *testing.T) {
	algo := &MD5PassSaltAlgo2{}
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("MD5PassSaltAlgo2.GetAlgoType() = %v, want AlgoIsStatic", got)
	}
}

func TestMD5CustomLizhiAlgo_NeedSalt(t *testing.T) {
	algo := &MD5PassSaltAlgo2{}
	if got := algo.NeedSalt(); !got {
		t.Errorf("MD5PassSaltAlgo2.NeedSalt() = %v, want true", got)
	}
}

func TestMD5CustomLizhiAlgo_SealAndRecover(t *testing.T) {
	algo := &MD5PassSaltAlgo2{}

	plain := "password"
	salt := "mysalt"
	token, err := algo.Seal(plain, salt)
	if err != nil {
		t.Fatalf("Seal() error = %v, want nil", err)
	}

	expected := md5Hex(salt + ";" + plain)
	if token != expected {
		t.Fatalf("Seal() = %q, want %q", token, expected)
	}

	recovered, err := algo.Recover(token, salt, plain)
	if err != nil {
		t.Fatalf("Recover() error = %v, want nil", err)
	}
	if recovered != plain {
		t.Fatalf("Recover() = %q, want %q", recovered, plain)
	}

	if _, err := algo.Recover(token, salt, "wrong"); err == nil {
		t.Fatalf("Recover() with wrong candidate expected error, got nil")
	}
}

func TestMD5CustomLizhiAlgo_Identify(t *testing.T) {
	algo := &MD5PassSaltAlgo2{}

	if !algo.Identify("5f4dcc3b5aa765d61d8327deb882cf99") {
		t.Fatalf("Identify() expected true for md5 hex")
	}
	if algo.Identify("deadbeef") {
		t.Fatalf("Identify() expected false for short token")
	}
}
