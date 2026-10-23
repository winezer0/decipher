package cracker

import (
	"context"
	"github.com/winezer0/decipher/internal/algo"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPredbCrack(t *testing.T) {
	preComputedDict := "mock(password)::password\nmock(123456)::123456\n"

	t.Run("Success", func(t *testing.T) {
		reader := strings.NewReader(preComputedDict)
		targets := []HashSaltTarget{
			{Hash: "mock(password)", Salt: ""},
		}
		targetMap := BuildTargetMap(targets)
		results := make(chan CrackerResult, 1)
		ctx := context.Background()

		engine := NewEngine(0, "", "")
		go func() {
			engine.PredbCrack(ctx, targetMap, reader, results, "mock", "static")
			close(results)
		}()

		select {
		case res := <-results:
			if res.Plaintext != "password" {
				t.Errorf("Expected plaintext 'password', got '%s'", res.Plaintext)
			}
			if res.Algorithm != "mock" {
				t.Errorf("Expected algorithm 'mock', got '%s'", res.Algorithm)
			}
		case <-time.After(time.Second):
			t.Error("Timeout waiting for result")
		}
	})

	t.Run("Failure", func(t *testing.T) {
		reader := strings.NewReader(preComputedDict)
		targets := []HashSaltTarget{
			{Hash: "mock(unknown)", Salt: ""},
		}
		targetMap := BuildTargetMap(targets)
		results := make(chan CrackerResult, 1)
		ctx := context.Background()

		engine := NewEngine(0, "", "")
		go func() {
			engine.PredbCrack(ctx, targetMap, reader, results, "mock", "static")
			close(results)
		}()

		count := 0
		for range results {
			count++
		}
		if count != 0 {
			t.Errorf("Expected 0 results, got %d", count)
		}
	})

	t.Run("WithContextCancellation", func(t *testing.T) {
		reader := strings.NewReader(preComputedDict)
		targets := []HashSaltTarget{
			{Hash: "mock(password)", Salt: ""},
		}
		targetMap := BuildTargetMap(targets)
		results := make(chan CrackerResult, 1)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		engine := NewEngine(0, "", "")
		engine.PredbCrack(ctx, targetMap, reader, results, "mock", "static")
	})

	t.Run("HashWithSalt", func(t *testing.T) {
		dictWithSalt := "hash123:mysalt:password123\n"
		reader := strings.NewReader(dictWithSalt)
		targets := []HashSaltTarget{
			{Hash: "hash123", Salt: "mysalt"},
		}
		targetMap := BuildTargetMap(targets)
		results := make(chan CrackerResult, 1)
		ctx := context.Background()

		engine := NewEngine(0, "", "")
		go func() {
			engine.PredbCrack(ctx, targetMap, reader, results, "mock", "static")
			close(results)
		}()

		select {
		case res := <-results:
			if res.Plaintext != "password123" {
				t.Errorf("Expected plaintext 'password123', got '%s'", res.Plaintext)
			}
			if res.Salt != "mysalt" {
				t.Errorf("Expected salt 'mysalt', got '%s'", res.Salt)
			}
		case <-time.After(time.Second):
			t.Error("Timeout waiting for result")
		}
	})

	t.Run("MultipleTargetsSameHash", func(t *testing.T) {
		reader := strings.NewReader("hash1::password1\n")
		targets := []HashSaltTarget{
			{Hash: "hash1", Salt: ""},
			{Hash: "hash1", Salt: "salt2"},
		}
		targetMap := BuildTargetMap(targets)
		results := make(chan CrackerResult, 2)
		ctx := context.Background()

		engine := NewEngine(0, "", "")
		go func() {
			engine.PredbCrack(ctx, targetMap, reader, results, "mock", "static")
			close(results)
		}()

		count := 0
		for range results {
			count++
		}
		if count != 2 {
			t.Errorf("Expected 2 results for 2 targets with same hash, got %d", count)
		}
	})
}

func TestRunLocalCrack(t *testing.T) {
	t.Run("EmptyTargets", func(t *testing.T) {
		engine := NewEngine(0, "", "")
		results := engine.RunPredbCrack(nil, nil)
		if len(results) != 0 {
			t.Errorf("Expected 0 results for empty targets, got %d", len(results))
		}
	})

	t.Run("EmptyCacheDir", func(t *testing.T) {
		engine := NewEngine(0, "", "")
		targets := []HashSaltTarget{{Hash: "testhash", Salt: ""}}
		results := engine.RunPredbCrack(targets, nil)
		if len(results) != 0 {
			t.Errorf("Expected 0 results for empty cache dir, got %d", len(results))
		}
	})

	t.Run("NonExistentCacheDir", func(t *testing.T) {
		engine := NewEngine(0, "", "")
		targets := []HashSaltTarget{{Hash: "testhash", Salt: ""}}

		results := engine.RunPredbCrack(targets, nil)
		if len(results) != 0 {
			t.Errorf("Expected 0 results for non-existent cache dir, got %d", len(results))
		}
	})

	findAlgos := algo.GetAlgorithmsByKeys([]string{"md5"}, false)
	t.Run("SuccessfulCrack", func(t *testing.T) {
		tempDir := t.TempDir()

		cacheContent := "e10adc3949ba59abbe56e057f20f883e::123456\n"
		cacheFile := filepath.Join(tempDir, "cache_md5($pass).predb")
		if err := os.WriteFile(cacheFile, []byte(cacheContent), 0644); err != nil {
			t.Fatalf("Failed to create cache file: %v", err)
		}

		engine := NewEngine(0, "", "")
		targets := []HashSaltTarget{{Hash: "e10adc3949ba59abbe56e057f20f883e", Salt: ""}}

		engine.PredbDir = tempDir
		results := engine.RunPredbCrack(targets, findAlgos)

		if len(results) != 1 {
			t.Errorf("Expected 1 result, got %d", len(results))
			return
		}

		if results[0].Plaintext != "123456" {
			t.Errorf("Expected plaintext '123456', got '%s'", results[0].Plaintext)
		}
		if results[0].Algorithm != "md5($pass)" {
			t.Errorf("Expected algorithm 'md5', got '%s'", results[0].Algorithm)
		}
	})

	t.Run("AlgorithmFilter", func(t *testing.T) {
		tempDir := t.TempDir()

		md5Cache := filepath.Join(tempDir, "cache_md5($pass).predb")
		sha1Cache := filepath.Join(tempDir, "cache_sha1($pass).predb")

		if err := os.WriteFile(md5Cache, []byte("hash1::pass1\n"), 0644); err != nil {
			t.Fatalf("Failed to create md5 cache: %v", err)
		}
		if err := os.WriteFile(sha1Cache, []byte("hash2::pass2\n"), 0644); err != nil {
			t.Fatalf("Failed to create sha1 cache: %v", err)
		}

		engine := NewEngine(0, "", "")
		targets := []HashSaltTarget{
			{Hash: "hash1", Salt: ""},
			{Hash: "hash2", Salt: ""},
		}

		engine.PredbDir = tempDir
		results := engine.RunPredbCrack(targets, findAlgos)

		if len(results) != 1 {
			t.Errorf("Expected 1 result (md5 only), got %d", len(results))
		}
		if len(results) > 0 && results[0].Algorithm != "md5($pass)" {
			t.Errorf("Expected md5 algorithm, got '%s'", results[0].Algorithm)
		}
	})

	t.Run("UseEngineCacheDir", func(t *testing.T) {
		tempDir := t.TempDir()

		cacheContent := "testhash::testpass\n"
		cacheFile := filepath.Join(tempDir, "cache_md5($pass).predb")
		if err := os.WriteFile(cacheFile, []byte(cacheContent), 0644); err != nil {
			t.Fatalf("Failed to create cache file: %v", err)
		}

		engine := NewEngine(0, tempDir, "")
		targets := []HashSaltTarget{{Hash: "testhash", Salt: ""}}

		results := engine.RunPredbCrack(targets, nil)

		if len(results) != 1 {
			t.Errorf("Expected 1 result using engine cacheDir, got %d", len(results))
		}
	})

	t.Run("HashFormatNormalization", func(t *testing.T) {
		tempDir := t.TempDir()

		cacheContent := "e10adc3949ba59abbe56e057f20f883e::123456\n"
		cacheFile := filepath.Join(tempDir, "cache_md5($pass).predb")
		if err := os.WriteFile(cacheFile, []byte(cacheContent), 0644); err != nil {
			t.Fatalf("Failed to create cache file: %v", err)
		}

		engine := NewEngine(0, "", "")

		targets := []HashSaltTarget{{Hash: "E10ADC3949BA59ABBE56E057F20F883E", Salt: ""}}
		engine.PredbDir = tempDir
		results := engine.RunPredbCrack(targets, nil)

		if len(results) != 1 {
			t.Errorf("Expected 1 result with normalized hash, got %d", len(results))
		}
	})

	t.Run("HashWithDashSeparator", func(t *testing.T) {
		tempDir := t.TempDir()

		cacheContent := "e10adc3949ba59abbe56e057f20f883e::123456\n"
		cacheFile := filepath.Join(tempDir, "cache_md5($pass).predb")
		if err := os.WriteFile(cacheFile, []byte(cacheContent), 0644); err != nil {
			t.Fatalf("Failed to create cache file: %v", err)
		}

		engine := NewEngine(0, "", "")

		targets := []HashSaltTarget{{Hash: "E10A-DC39-49BA-59AB-BE56-E057-F20F-883E", Salt: ""}}
		engine.PredbDir = tempDir
		results := engine.RunPredbCrack(targets, nil)

		if len(results) != 1 {
			t.Errorf("Expected 1 result with dash-separated hash, got %d", len(results))
		}
	})

	t.Run("MultipleCacheFiles", func(t *testing.T) {
		tempDir := t.TempDir()

		cache1 := filepath.Join(tempDir, "cache_md5($pass).predb")
		cache2 := filepath.Join(tempDir, "cache_sha1($pass).predb")

		if err := os.WriteFile(cache1, []byte("hash1::pass1\n"), 0644); err != nil {
			t.Fatalf("Failed to create cache1: %v", err)
		}
		if err := os.WriteFile(cache2, []byte("hash2::pass2\n"), 0644); err != nil {
			t.Fatalf("Failed to create cache2: %v", err)
		}

		engine := NewEngine(0, "", "")
		targets := []HashSaltTarget{
			{Hash: "hash1", Salt: ""},
			{Hash: "hash2", Salt: ""},
		}

		engine.PredbDir = tempDir
		results := engine.RunPredbCrack(targets, nil)

		if len(results) != 2 {
			t.Errorf("Expected 2 results from 2 cache files, got %d", len(results))
		}
	})

	t.Run("DuplicateResults", func(t *testing.T) {
		tempDir := t.TempDir()

		cacheContent := "hash1::password\nhash1::password\n"
		cacheFile := filepath.Join(tempDir, "cache_md5($pass).predb")
		if err := os.WriteFile(cacheFile, []byte(cacheContent), 0644); err != nil {
			t.Fatalf("Failed to create cache file: %v", err)
		}

		engine := NewEngine(0, "", "")
		targets := []HashSaltTarget{{Hash: "hash1", Salt: ""}}

		engine.PredbDir = tempDir
		results := engine.RunPredbCrack(targets, nil)

		if len(results) != 1 {
			t.Errorf("Expected 1 result (duplicates removed), got %d", len(results))
		}
	})
}
