package sha

import (
	"testing"

	"decipher/internal/algo/types"
)

func TestSHA1CustomYYKAlgo_Name(t *testing.T) {
	algo := &SHA1CustomYYKAlgo{}
	if got := algo.Name(); got != "sha1_custom_yyk" {
		t.Errorf("SHA1CustomYYKAlgo.Name() = %v, want sha1_custom_yyk", got)
	}
}

func TestSHA1CustomYYKAlgo_GetAlgoType(t *testing.T) {
	algo := &SHA1CustomYYKAlgo{}
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("SHA1CustomYYKAlgo.GetAlgoType() = %v, want AlgoIsStatic", got)
	}
}

func TestSHA1CustomYYKAlgo_NeedSalt(t *testing.T) {
	algo := &SHA1CustomYYKAlgo{}
	if got := algo.NeedSalt(); !got {
		t.Errorf("SHA1CustomYYKAlgo.NeedSalt() = %v, want true", got)
	}
}

func TestSHA1CustomYYKAlgo_SealAndRecover(t *testing.T) {
	algo := &SHA1CustomYYKAlgo{}

	plain := "password"
	salt := "mysalt"
	token, err := algo.Seal(plain, salt)
	if err != nil {
		t.Fatalf("Seal() error = %v, want nil", err)
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

func TestSHA1CustomYYKAlgo_Identify(t *testing.T) {
	algo := &SHA1CustomYYKAlgo{}

	if !algo.Identify("a9993e364706816aba3e25717850c26c9cd0d89d") {
		t.Fatalf("Identify() expected true for sha1 hex")
	}
	if algo.Identify("deadbeef") {
		t.Fatalf("Identify() expected false for short token")
	}
}
