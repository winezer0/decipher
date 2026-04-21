package bcrypt

import (
	"testing"
)

func TestBcryptPassSaltAlgo(t *testing.T) {
	algo := &BcryptPassSaltAlgo{}

	// Test data
	plaintext := "password123"
	salt := "randomSalt"
	wrongPlain := "password321"
	wrongSalt := "wrongSalt"

	t.Run("Name Check", func(t *testing.T) {
		if algo.Name() != "bcrypt($pass.$salt)" {
			t.Errorf("Expected name 'bcrypt_pass_salt', got '%s'", algo.Name())
		}
	})

	t.Run("NeedAddToPredb Check", func(t *testing.T) {
		if algo.NeedAddToPredb() {
			t.Error("Expected NeedAddToPredb to be false")
		}
	})

	t.Run("Seal and Recover Success", func(t *testing.T) {
		// Test Seal
		hash, err := algo.Seal(plaintext, salt)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}
		if hash == "" {
			t.Fatal("Seal returned empty hash")
		}
		t.Logf("Generated hash: %s", hash)

		// Test Recover (Success)
		recovered, err := algo.Recover(hash, salt, plaintext)
		if err != nil {
			t.Errorf("Recover failed for correct credentials: %v", err)
		}
		if recovered != plaintext {
			t.Errorf("Recover returned wrong plaintext: got %s, want %s", recovered, plaintext)
		}
	})

	t.Run("Recover Failure - Wrong Plaintext", func(t *testing.T) {
		// Generate hash first
		hash, _ := algo.Seal(plaintext, salt)

		_, err := algo.Recover(hash, salt, wrongPlain)
		if err == nil {
			t.Error("Recover should fail for wrong plaintext, but it succeeded")
		}
	})

	t.Run("Recover Failure - Wrong Salt", func(t *testing.T) {
		// Generate hash first
		hash, _ := algo.Seal(plaintext, salt)

		_, err := algo.Recover(hash, wrongSalt, plaintext)
		if err == nil {
			t.Error("Recover should fail for wrong salt, but it succeeded")
		}
	})
}
