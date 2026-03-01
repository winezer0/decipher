package cracker

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"decipher/internal/algo"
	"decipher/internal/algo/types"
)

func TestCrackByPreDB(t *testing.T) {
	preComputedDict := "mock(password)::password\nmock(123456)::123456\n"

	t.Run("Success", func(t *testing.T) {
		reader := strings.NewReader(preComputedDict)
		targets := []Target{
			{Hash: "mock(password)", Salt: ""},
		}
		results := make(chan CrackerResult, 1)
		ctx := context.Background()

		engine := NewEngine(0, "")
		go func() {
			engine.loacalPreDBCrack(ctx, targets, reader, results, "mock", "static")
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
		targets := []Target{
			{Hash: "mock(unknown)", Salt: ""},
		}
		results := make(chan CrackerResult, 1)
		ctx := context.Background()

		engine := NewEngine(0, "")
		go func() {
			engine.loacalPreDBCrack(ctx, targets, reader, results, "mock", "static")
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
		targets := []Target{
			{Hash: "mock(password)", Salt: ""},
		}
		results := make(chan CrackerResult, 1)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		engine := NewEngine(0, "")
		engine.loacalPreDBCrack(ctx, targets, reader, results, "mock", "static")
	})

	t.Run("HashWithSalt", func(t *testing.T) {
		dictWithSalt := "hash123:mysalt:password123\n"
		reader := strings.NewReader(dictWithSalt)
		targets := []Target{
			{Hash: "hash123", Salt: "mysalt"},
		}
		results := make(chan CrackerResult, 1)
		ctx := context.Background()

		engine := NewEngine(0, "")
		go func() {
			engine.loacalPreDBCrack(ctx, targets, reader, results, "mock", "static")
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
		targets := []Target{
			{Hash: "hash1", Salt: ""},
			{Hash: "hash1", Salt: "salt2"},
		}
		results := make(chan CrackerResult, 2)
		ctx := context.Background()

		engine := NewEngine(0, "")
		go func() {
			engine.loacalPreDBCrack(ctx, targets, reader, results, "mock", "static")
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

func TestParseSalts(t *testing.T) {
	t.Run("EmptySalts", func(t *testing.T) {
		salts, sig := parseSalts(nil)
		if len(salts) != 1 || salts[0] != "" {
			t.Errorf("Expected empty salt, got %v", salts)
		}
		if sig != "None" {
			t.Errorf("Expected signature 'None', got %s", sig)
		}
	})

	t.Run("RawSalt", func(t *testing.T) {
		salts, sig := parseSalts([]string{"rawsalt"})
		if len(salts) != 1 || salts[0] != "rawsalt" {
			t.Errorf("Expected ['rawsalt'], got %v", salts)
		}
		if sig != "Raw:rawsalt" {
			t.Errorf("Expected signature 'Raw:rawsalt', got %s", sig)
		}
	})

	t.Run("SaltFromFile", func(t *testing.T) {
		tempFile, err := os.CreateTemp("", "salts_*.txt")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer os.Remove(tempFile.Name())

		if _, err := tempFile.WriteString("salt1\nsalt2\n"); err != nil {
			t.Fatalf("Failed to write temp file: %v", err)
		}
		tempFile.Close()

		salts, _ := parseSalts([]string{tempFile.Name()})
		if len(salts) != 2 {
			t.Errorf("Expected 2 salts, got %d", len(salts))
		}
	})
}

func TestBuildDictTasks(t *testing.T) {
	t.Run("NoTasksDefaultsToBuiltin", func(t *testing.T) {
		tasks := buildDictTasks(nil)
		if len(tasks) != 1 {
			t.Errorf("Expected 1 task (Builtin), got %d", len(tasks))
		}
		if tasks[0].Name != "Builtin Dict" {
			t.Errorf("Expected 'Builtin Dict', got %s", tasks[0].Name)
		}
	})

	t.Run("CustomDict", func(t *testing.T) {
		tempFile, err := os.CreateTemp("", "dict_*.txt")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer os.Remove(tempFile.Name())
		tempFile.Close()

		tasks := buildDictTasks([]string{tempFile.Name()})
		if len(tasks) != 1 {
			t.Errorf("Expected 1 task, got %d", len(tasks))
		}
	})
}

func TestDeduplicateCache(t *testing.T) {
	t.Run("NonExistentDir", func(t *testing.T) {
		DeduplicateCache("/nonexistent/path")
	})

	t.Run("EmptyDir", func(t *testing.T) {
		tempDir := t.TempDir()
		DeduplicateCache(tempDir)
	})

	t.Run("WithCacheFile", func(t *testing.T) {
		tempDir := t.TempDir()
		cacheFile := filepath.Join(tempDir, "cache_md5.cache")
		content := "hash1::pass1\nhash1::pass1\nhash2::pass2\n"
		if err := os.WriteFile(cacheFile, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create cache file: %v", err)
		}

		DeduplicateCache(tempDir)

		data, err := os.ReadFile(cacheFile)
		if err != nil {
			t.Fatalf("Failed to read cache file: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) != 2 {
			t.Errorf("Expected 2 unique lines after dedup, got %d", len(lines))
		}
	})
}

func TestGenCacheDBConcurrency(t *testing.T) {
	tempDir := t.TempDir()

	content := "password\n123456\nadmin\n"
	scanner := bufio.NewScanner(strings.NewReader(content))

	mockAlgos := []algo.Algorithm{&mockAlgo{name: "test"}}

	genCacheDBConcurrency(scanner, mockAlgos, []string{""}, 2, tempDir)

	cacheFile := filepath.Join(tempDir, "cache_test.cache")
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		t.Error("Cache file was not created")
	}
}

type mockAlgo struct {
	name string
}

func (m *mockAlgo) Name() string {
	return m.name
}

func (m *mockAlgo) GetAlgoType() types.AlgoType {
	return types.AlgoIsStatic
}

func (m *mockAlgo) NeedsPrecomputation() bool {
	return true
}

func (m *mockAlgo) Seal(plaintext, secret string) (string, error) {
	return "hash_" + plaintext, nil
}

func (m *mockAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := m.Seal(candidatePlain, secret)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}
