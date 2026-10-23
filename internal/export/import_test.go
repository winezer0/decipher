package export

import (
	"github.com/winezer0/decipher/internal/cracker"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSuccessCacheMap(t *testing.T) {
	tempDir := t.TempDir()
	cacheFile := filepath.Join(tempDir, "success.predb.csv")

	// Create a dummy cache file
	content := "hash_salt,clear_text,salt,algo,algo_type\n" +
		"e10adc3949ba59abbe56e057f20f883e,123456,,md5,static\n" +
		"5d41402abc4b2a76b9719d911017c592:world,hello,world,md5,static\n"
	if err := os.WriteFile(cacheFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp cache file: %v", err)
	}

	// Test loading
	cracked := LoadSuccessCacheMap(cacheFile, []cracker.HashSaltTarget{
		{Hash: "e10adc3949ba59abbe56e057f20f883e"},
		{Hash: "5d41402abc4b2a76b9719d911017c592"},
	})

	if len(cracked) != 2 {
		t.Errorf("Expected 2 cached results, got %d", len(cracked))
	}

	// Check first result
	if res, ok := cracked["e10adc3949ba59abbe56e057f20f883e"]; !ok {
		t.Error("Expected hash e10adc3949ba59abbe56e057f20f883e to be cached")
	} else {
		if res.Plaintext != "123456" {
			t.Errorf("Expected plaintext '123456', got '%s'", res.Plaintext)
		}
		if res.Algorithm != "md5" {
			t.Errorf("Expected algorithm 'md5', got '%s'", res.Algorithm)
		}
	}

	// Check second result
	if res, ok := cracked["5d41402abc4b2a76b9719d911017c592"]; !ok {
		t.Error("Expected hash 5d41402abc4b2a76b9719d911017c592 to be cached")
	} else {
		if res.Plaintext != "hello" {
			t.Errorf("Expected plaintext 'hello', got '%s'", res.Plaintext)
		}
		if res.Salt != "world" {
			t.Errorf("Expected salt 'world', got '%s'", res.Salt)
		}
	}
}

func TestLoadSuccessCacheMap_NonExistent(t *testing.T) {
	cracked := LoadSuccessCacheMap("non_existent_file.csv", []cracker.HashSaltTarget{{Hash: "missing"}})
	if len(cracked) != 0 {
		t.Errorf("Expected empty map for non-existent file, got %d entries", len(cracked))
	}
}

func TestLoadSuccessCacheMap_Empty(t *testing.T) {
	tempDir := t.TempDir()
	cacheFile := filepath.Join(tempDir, "empty.csv")
	if err := os.WriteFile(cacheFile, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to create empty file: %v", err)
	}

	cracked := LoadSuccessCacheMap(cacheFile, []cracker.HashSaltTarget{{Hash: "missing"}})
	if len(cracked) != 0 {
		t.Errorf("Expected empty map for empty file, got %d entries", len(cracked))
	}
}
