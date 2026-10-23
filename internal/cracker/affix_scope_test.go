package cracker

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/winezer0/decipher/internal/algo"
)

// TestPredbScopeSeparatesAffixConfigurations checks cached hashes are isolated by affixes.
func TestPredbScopeSeparatesAffixConfigurations(t *testing.T) {
	root := t.TempDir()
	plainPath := filepath.Join(root, "plain.txt")
	if err := os.WriteFile(plainPath, []byte("password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	algorithm := algo.GetAlgorithmByName("md5($pass)")
	configured := NewEngineWithAffix(1, filepath.Join(root, "data"), filepath.Join(root, "run"), "pre-", "-post", "", "")
	if err := configured.CreatePredb([]string{plainPath}, nil, []algo.Algorithm{algorithm}); err != nil {
		t.Fatal(err)
	}

	digest := md5.Sum([]byte("pre-password-post"))
	hash := hex.EncodeToString(digest[:])
	got := configured.RunPredbCrack([]HashSaltTarget{{Hash: hash}}, []algo.Algorithm{algorithm})
	want := []CrackerResult{{Hash: hash, Algorithm: algorithm.Name(), AlgoType: string(algorithm.GetAlgoType()), Plaintext: "password"}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("configured affix predb results = %#v, want %#v", got, want)
	}

	other := NewEngineWithAffix(1, configured.PredbDir, filepath.Join(root, "run"), "other-", "", "", "")
	if mismatched := other.RunPredbCrack([]HashSaltTarget{{Hash: hash}}, []algo.Algorithm{algorithm}); len(mismatched) != 0 {
		t.Fatalf("different affix configuration reused predb results: %#v", mismatched)
	}
	if configured.GetSuccessCachePath() == other.GetSuccessCachePath() {
		t.Fatal("success cache path must be scoped to the affix configuration")
	}
}

// TestDeduplicateCacheIncludesAffixScopes checks maintenance includes scoped predb files.
func TestDeduplicateCacheIncludesAffixScopes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "affix-config", "cache_md5($pass).predb")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("one\none\ntwo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := DeduplicateCache(filepath.Dir(filepath.Dir(path))); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "one\ntwo\n" {
		t.Fatalf("deduplicated scoped predb = %q, want %q", got, "one\ntwo\n")
	}
}
