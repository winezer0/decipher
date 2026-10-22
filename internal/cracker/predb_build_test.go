package cracker

import (
	"decipher/internal/algo"
	"decipher/internal/algo/md5"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreatePredb(t *testing.T) {
	// Setup temp dir
	tmpDir := t.TempDir()

	// Create plain file
	plainFile := filepath.Join(tmpDir, "plain.txt")
	err := os.WriteFile(plainFile, []byte("password\n123456\n"), 0644)
	if err != nil {
		t.Fatalf("Failed to create plain file: %v", err)
	}

	// Setup Engine
	predbDir := filepath.Join(tmpDir, "predb")
	engine := NewEngine(2, predbDir, "")

	// Setup Algos
	// MD5 is unsalted, SaltPass is salted
	md5Algo := &md5.MD5Algo{}
	md5SaltAlgo := &md5.MD5SaltPassAlgo{}
	algos := []algo.Algorithm{md5Algo, md5SaltAlgo}

	// Call CreatePredb
	// Empty secret dicts -> Empty salt provider -> Salted algo should use empty salt?
	// Wait, if no secret dicts, InitSaltProviders adds empty salt provider.
	err = engine.CreatePredb([]string{plainFile}, []string{}, algos)
	if err != nil {
		t.Fatalf("CreatePredb failed: %v", err)
	}

	// Verify Output Files
	// MD5 file: cache_md5.predb
	// Algo Name is "md5"
	md5File := filepath.Join(predbDir, "cache_md5($pass).predb")
	if !fileExists(md5File) {
		t.Errorf("Expected cache_md5($pass).predb to exist")
	} else {
		content := readFile(t, md5File)
		// password -> 5f4dcc3b5aa765d61d8327deb882cf99
		// Format: hash:salt:plain
		// 5f4dcc3b5aa765d61d8327deb882cf99::password
		if !strings.Contains(content, "5f4dcc3b5aa765d61d8327deb882cf99::password") {
			t.Errorf("cache_md5.predb missing password hash or format incorrect. Content: %s", content)
		}
	}
}

func TestCreatePredbReturnsInputErrors(t *testing.T) {
	for _, input := range []string{"missing", "oversized line"} {
		t.Run(input, func(t *testing.T) {
			dir := t.TempDir()
			plainFile := filepath.Join(dir, "plain.txt")
			if input == "oversized line" {
				if err := os.WriteFile(plainFile, []byte(strings.Repeat("x", 128*1024)), 0644); err != nil {
					t.Fatal(err)
				}
			}
			engine := &Engine{workers: 1, PredbDir: dir}
			if err := engine.CreatePredb([]string{plainFile}, nil, []algo.Algorithm{&md5.MD5Algo{}}); err == nil {
				t.Fatal("expected input error, got success")
			}
		})
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readFile(t *testing.T, path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read file %s: %v", path, err)
	}
	return string(b)
}
