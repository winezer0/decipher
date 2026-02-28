package cracker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunLocalCrack(t *testing.T) {
	t.Run("EmptyTargets", func(t *testing.T) {
		engine := NewEngine(0, "")
		results := engine.RunLocalCrack(nil, "", nil)
		if len(results) != 0 {
			t.Errorf("Expected 0 results for empty targets, got %d", len(results))
		}
	})

	t.Run("EmptyCacheDir", func(t *testing.T) {
		engine := NewEngine(0, "")
		targets := []Target{{Hash: "testhash", Salt: ""}}
		tempDir := t.TempDir()

		results := engine.RunLocalCrack(targets, tempDir, nil)
		if len(results) != 0 {
			t.Errorf("Expected 0 results for empty cache dir, got %d", len(results))
		}
	})

	t.Run("NonExistentCacheDir", func(t *testing.T) {
		engine := NewEngine(0, "")
		targets := []Target{{Hash: "testhash", Salt: ""}}

		results := engine.RunLocalCrack(targets, "/nonexistent/path", nil)
		if len(results) != 0 {
			t.Errorf("Expected 0 results for non-existent cache dir, got %d", len(results))
		}
	})

	t.Run("SuccessfulCrack", func(t *testing.T) {
		tempDir := t.TempDir()

		cacheContent := "e10adc3949ba59abbe56e057f20f883e::123456\n"
		cacheFile := filepath.Join(tempDir, "cache_md5.cache")
		if err := os.WriteFile(cacheFile, []byte(cacheContent), 0644); err != nil {
			t.Fatalf("Failed to create cache file: %v", err)
		}

		engine := NewEngine(0, "")
		targets := []Target{{Hash: "e10adc3949ba59abbe56e057f20f883e", Salt: ""}}

		results := engine.RunLocalCrack(targets, tempDir, []string{"md5"})

		if len(results) != 1 {
			t.Errorf("Expected 1 result, got %d", len(results))
			return
		}

		if results[0].Plaintext != "123456" {
			t.Errorf("Expected plaintext '123456', got '%s'", results[0].Plaintext)
		}
		if results[0].Algorithm != "md5" {
			t.Errorf("Expected algorithm 'md5', got '%s'", results[0].Algorithm)
		}
	})

	t.Run("AlgorithmFilter", func(t *testing.T) {
		tempDir := t.TempDir()

		md5Cache := filepath.Join(tempDir, "cache_md5.cache")
		sha1Cache := filepath.Join(tempDir, "cache_sha1.cache")

		if err := os.WriteFile(md5Cache, []byte("hash1::pass1\n"), 0644); err != nil {
			t.Fatalf("Failed to create md5 cache: %v", err)
		}
		if err := os.WriteFile(sha1Cache, []byte("hash2::pass2\n"), 0644); err != nil {
			t.Fatalf("Failed to create sha1 cache: %v", err)
		}

		engine := NewEngine(0, "")
		targets := []Target{
			{Hash: "hash1", Salt: ""},
			{Hash: "hash2", Salt: ""},
		}

		results := engine.RunLocalCrack(targets, tempDir, []string{"md5"})

		if len(results) != 1 {
			t.Errorf("Expected 1 result (md5 only), got %d", len(results))
		}
		if len(results) > 0 && results[0].Algorithm != "md5" {
			t.Errorf("Expected md5 algorithm, got '%s'", results[0].Algorithm)
		}
	})

	t.Run("UseEngineCacheDir", func(t *testing.T) {
		tempDir := t.TempDir()

		cacheContent := "testhash::testpass\n"
		cacheFile := filepath.Join(tempDir, "cache_md5.cache")
		if err := os.WriteFile(cacheFile, []byte(cacheContent), 0644); err != nil {
			t.Fatalf("Failed to create cache file: %v", err)
		}

		engine := NewEngine(0, tempDir)
		targets := []Target{{Hash: "testhash", Salt: ""}}

		results := engine.RunLocalCrack(targets, "", nil)

		if len(results) != 1 {
			t.Errorf("Expected 1 result using engine cacheDir, got %d", len(results))
		}
	})

	t.Run("HashFormatNormalization", func(t *testing.T) {
		tempDir := t.TempDir()

		cacheContent := "e10adc3949ba59abbe56e057f20f883e::123456\n"
		cacheFile := filepath.Join(tempDir, "cache_md5.cache")
		if err := os.WriteFile(cacheFile, []byte(cacheContent), 0644); err != nil {
			t.Fatalf("Failed to create cache file: %v", err)
		}

		engine := NewEngine(0, "")

		targets := []Target{{Hash: "E10ADC3949BA59ABBE56E057F20F883E", Salt: ""}}
		results := engine.RunLocalCrack(targets, tempDir, nil)

		if len(results) != 1 {
			t.Errorf("Expected 1 result with normalized hash, got %d", len(results))
		}
	})

	t.Run("HashWithDashSeparator", func(t *testing.T) {
		tempDir := t.TempDir()

		cacheContent := "e10adc3949ba59abbe56e057f20f883e::123456\n"
		cacheFile := filepath.Join(tempDir, "cache_md5.cache")
		if err := os.WriteFile(cacheFile, []byte(cacheContent), 0644); err != nil {
			t.Fatalf("Failed to create cache file: %v", err)
		}

		engine := NewEngine(0, "")

		targets := []Target{{Hash: "E10A-DC39-49BA-59AB-BE56-E057-F20F-883E", Salt: ""}}
		results := engine.RunLocalCrack(targets, tempDir, nil)

		if len(results) != 1 {
			t.Errorf("Expected 1 result with dash-separated hash, got %d", len(results))
		}
	})

	t.Run("MultipleCacheFiles", func(t *testing.T) {
		tempDir := t.TempDir()

		cache1 := filepath.Join(tempDir, "cache_md5.cache")
		cache2 := filepath.Join(tempDir, "cache_sha1.cache")

		if err := os.WriteFile(cache1, []byte("hash1::pass1\n"), 0644); err != nil {
			t.Fatalf("Failed to create cache1: %v", err)
		}
		if err := os.WriteFile(cache2, []byte("hash2::pass2\n"), 0644); err != nil {
			t.Fatalf("Failed to create cache2: %v", err)
		}

		engine := NewEngine(0, "")
		targets := []Target{
			{Hash: "hash1", Salt: ""},
			{Hash: "hash2", Salt: ""},
		}

		results := engine.RunLocalCrack(targets, tempDir, nil)

		if len(results) != 2 {
			t.Errorf("Expected 2 results from 2 cache files, got %d", len(results))
		}
	})

	t.Run("DuplicateResults", func(t *testing.T) {
		tempDir := t.TempDir()

		cacheContent := "hash1::password\nhash1::password\n"
		cacheFile := filepath.Join(tempDir, "cache_md5.cache")
		if err := os.WriteFile(cacheFile, []byte(cacheContent), 0644); err != nil {
			t.Fatalf("Failed to create cache file: %v", err)
		}

		engine := NewEngine(0, "")
		targets := []Target{{Hash: "hash1", Salt: ""}}

		results := engine.RunLocalCrack(targets, tempDir, nil)

		if len(results) != 1 {
			t.Errorf("Expected 1 result (duplicates removed), got %d", len(results))
		}
	})
}
