package cracker

import (
	"os"
	"path/filepath"
	"testing"

	"decipher/internal/algo"
	"decipher/internal/algo/types"
)

type mockDynamicSaltAlgo struct{}

func (m *mockDynamicSaltAlgo) Name() string { return "mockDynamicSalt" }

func (m *mockDynamicSaltAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsDynamic }

func (m *mockDynamicSaltAlgo) NeedSalt() bool { return true }

func (m *mockDynamicSaltAlgo) NeedAddToPredb() bool { return false }

func (m *mockDynamicSaltAlgo) Seal(plaintext, secret string) (string, error) { return "", nil }

func (m *mockDynamicSaltAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	if token == "HASH" && secret == "mysalt" && candidatePlain == "password" {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}
func (m *mockDynamicSaltAlgo) Identify(token string) bool { return true }

func TestRunDynamicCrack_SupportSecretsFile(t *testing.T) {
	tempDir := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}
	defer func() { _ = os.Chdir(oldWd) }()

	dictPath := filepath.Join(tempDir, "dict.txt")
	if err := os.WriteFile(dictPath, []byte("password\n"), 0644); err != nil {
		t.Fatalf("write dict failed: %v", err)
	}

	secretPath := filepath.Join(tempDir, "salts.txt")
	if err := os.WriteFile(secretPath, []byte("wrong\nmysalt\n"), 0644); err != nil {
		t.Fatalf("write salts failed: %v", err)
	}

	engine := NewEngine(2, "", "")

	targets := []HashSaltTarget{{Hash: "HASH", Salt: ""}}
	results := engine.RunHashCrack(targets, []string{dictPath}, []string{secretPath}, []algo.Algorithm{&mockDynamicSaltAlgo{}})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Plaintext != "password" {
		t.Fatalf("expected plaintext password, got %q", results[0].Plaintext)
	}
	if results[0].Salt != "mysalt" {
		t.Fatalf("expected salt mysalt, got %q", results[0].Salt)
	}
}

func TestRunDynamicCrack_UsesTargetSaltWhenPresent(t *testing.T) {
	tempDir := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}
	defer func() { _ = os.Chdir(oldWd) }()

	dictPath := filepath.Join(tempDir, "dict.txt")
	if err := os.WriteFile(dictPath, []byte("password\n"), 0644); err != nil {
		t.Fatalf("write dict failed: %v", err)
	}

	engine := NewEngine(2, "", "")

	targets := []HashSaltTarget{{Hash: "HASH", Salt: "mysalt"}}
	results := engine.RunHashCrack(targets, []string{dictPath}, []string{"wrong"}, []algo.Algorithm{&mockDynamicSaltAlgo{}})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Salt != "mysalt" {
		t.Fatalf("expected salt mysalt, got %q", results[0].Salt)
	}
}
