package sdk

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/winezer0/decipher/internal/algo/des"
)

// TestNewClientCreatesConfiguredAndDefaultDirectories checks client initialization paths.
func TestNewClientCreatesConfiguredAndDefaultDirectories(t *testing.T) {
	t.Run("configured directories", func(t *testing.T) {
		root := t.TempDir()
		client, err := NewClient(Config{
			Workers:     1,
			DataDir:     filepath.Join(root, "data"),
			RunCacheDir: filepath.Join(root, "cache"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if client == nil {
			t.Fatal("expected client")
		}
		for _, path := range []string{filepath.Join(root, "data"), filepath.Join(root, "cache")} {
			info, err := os.Stat(path)
			if err != nil || !info.IsDir() {
				t.Fatalf("expected directory %q, got info=%v err=%v", path, info, err)
			}
		}
	})

	t.Run("default directories", func(t *testing.T) {
		root := t.TempDir()
		t.Setenv("XDG_CACHE_HOME", root)
		t.Setenv("LOCALAPPDATA", root)
		base, err := defaultDataDir()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(base, root) {
			t.Fatalf("default data directory %q is outside test root %q", base, root)
		}
		if _, err := NewClient(Config{}); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{filepath.Join(base, "data"), filepath.Join(base, "cache")} {
			if info, err := os.Stat(path); err != nil || !info.IsDir() {
				t.Fatalf("expected default directory %q, got info=%v err=%v", path, info, err)
			}
		}
	})

	t.Run("negative worker count", func(t *testing.T) {
		if _, err := NewClient(Config{Workers: -1}); err == nil {
			t.Fatal("expected negative worker count to fail")
		}
	})

	t.Run("data path is a file", func(t *testing.T) {
		root := t.TempDir()
		blocker := filepath.Join(root, "not-a-directory")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := NewClient(Config{
			DataDir:     filepath.Join(blocker, "data"),
			RunCacheDir: filepath.Join(root, "cache"),
		})
		if err == nil {
			t.Fatal("expected invalid data directory to fail")
		}
	})
}

// TestListAlgorithmsAndIdentify checks metadata and in-memory hash identification.
func TestListAlgorithmsAndIdentify(t *testing.T) {
	client := newTestClient(t)
	algorithms := client.ListAlgorithms()
	if len(algorithms) == 0 {
		t.Fatal("expected supported algorithms")
	}
	foundMD5 := false
	for _, algorithm := range algorithms {
		if algorithm.Name == "md5($pass)" && algorithm.Type == "static" && algorithm.NeedsPrecomputation {
			foundMD5 = true
		}
	}
	if !foundMD5 {
		t.Fatalf("expected md5 metadata in complete list: %#v", algorithms)
	}

	got := client.Identify([]string{"", "# comment", "5d41402abc4b2a76b9719d911017c592:salt"})
	if len(got) != 1 || got[0].Hash != "5d41402abc4b2a76b9719d911017c592" {
		t.Fatalf("unexpected identification results: %#v", got)
	}
	if !contains(got[0].Algorithms, "md5($pass)") {
		t.Fatalf("expected MD5 algorithm match: %#v", got[0].Algorithms)
	}
}

// TestBuiltinDictionaryFunctionsInitializeAndAppendMemoryValues checks SDK dictionary operations.
func TestBuiltinDictionaryFunctionsInitializeAndAppendMemoryValues(t *testing.T) {
	root := t.TempDir()
	client, err := NewClient(Config{
		DataDir:     filepath.Join(root, "data"),
		RunCacheDir: filepath.Join(root, "cache"),
	})
	if err != nil {
		t.Fatal(err)
	}
	plainPath := filepath.Join(root, "data", "builtin-plain.txt")
	saltPath := filepath.Join(root, "data", "builtin-salt.txt")
	initialPlain, err := os.ReadFile(plainPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(initialPlain) == 0 {
		t.Fatal("expected initialized plaintext dictionary")
	}
	if err := client.AddPlaintexts([]string{"sdk-plain-a", "sdk-plain-b"}); err != nil {
		t.Fatal(err)
	}
	if err := client.AddSecrets([]string{"sdk-salt"}); err != nil {
		t.Fatal(err)
	}
	if err := client.InitBuiltinDictionaries(); err != nil {
		t.Fatal(err)
	}
	plainAfter, err := os.ReadFile(plainPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(plainAfter), string(initialPlain)) ||
		!strings.Contains(string(plainAfter), "sdk-plain-a\nsdk-plain-b\n") {
		t.Fatalf("plaintext dictionary was not preserved/appended: %q", plainAfter)
	}
	saltAfter, err := os.ReadFile(saltPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(saltAfter), "sdk-salt\n") {
		t.Fatalf("salt dictionary value was not appended: %q", saltAfter)
	}
	if err := client.AddPlaintexts([]string{"bad\nvalue"}); err == nil {
		t.Fatal("expected line breaks to be rejected")
	}
}

// TestCrackWithBuiltinDictionariesUsesPersistedValues checks dictionary additions are usable in live cracking.
func TestCrackWithBuiltinDictionariesUsesPersistedValues(t *testing.T) {
	client := newTestClient(t)
	plainPath := client.engine.GetBuiltinPlainPath()
	saltPath := client.engine.GetBuiltinSaltPath()
	if err := os.WriteFile(plainPath, []byte("seed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(saltPath, []byte("seed-salt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := client.AddPlaintexts([]string{"hello"}); err != nil {
		t.Fatal(err)
	}
	if err := client.AddSecrets([]string{"salt"}); err != nil {
		t.Fatal(err)
	}
	digest := md5.Sum([]byte("hellosalt"))
	hash := hex.EncodeToString(digest[:])
	got, err := client.CrackWithBuiltinDictionaries([]string{hash}, []string{"md5($pass.$salt)"}, Affixes{})
	if err != nil {
		t.Fatal(err)
	}
	want := []Result{{
		Hash:      hash,
		Algorithm: "md5($pass.$salt)",
		Type:      "static",
		Plaintext: "hello",
		Salt:      "salt",
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected builtin dictionary crack results: got %#v want %#v", got, want)
	}

	affixes := Affixes{PassPrefix: "P-", SaltSuffix: "-S"}
	affixedDigest := md5.Sum([]byte("P-hellosalt-S"))
	affixedHash := hex.EncodeToString(affixedDigest[:])
	affixed, err := client.CrackWithBuiltinDictionaries([]string{affixedHash}, []string{"md5($pass.$salt)"}, affixes)
	if err != nil {
		t.Fatal(err)
	}
	wantAffixed := []Result{{Hash: affixedHash, Algorithm: "md5($pass.$salt)", Type: "static", Plaintext: "P-hello", Salt: "salt"}}
	if !reflect.DeepEqual(affixed, wantAffixed) {
		t.Fatalf("unexpected affixed builtin crack results: got %#v want %#v", affixed, wantAffixed)
	}
}

// TestInMemoryEncryptDecryptAndJSON checks the in-memory reversible flow and JSON-ready results.
func TestInMemoryEncryptDecryptAndJSON(t *testing.T) {
	client := newTestClient(t)
	encrypted, err := client.Encrypt([]string{"hello", "world"}, nil, []string{"base64($pass)"}, Affixes{})
	if err != nil {
		t.Fatal(err)
	}
	expectedEncrypted := []EncryptionResult{
		{Algorithm: "base64($pass)", Hash: "aGVsbG8=", Plaintext: "hello"},
		{Algorithm: "base64($pass)", Hash: "d29ybGQ=", Plaintext: "world"},
	}
	if !reflect.DeepEqual(encrypted, expectedEncrypted) {
		t.Fatalf("unexpected encryption results: got %#v want %#v", encrypted, expectedEncrypted)
	}
	encoded, err := json.Marshal(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	expectedJSON := `[{"algorithm":"base64($pass)","hash":"aGVsbG8=","salt":"","plaintext":"hello"},{"algorithm":"base64($pass)","hash":"d29ybGQ=","salt":"","plaintext":"world"}]`
	if string(encoded) != expectedJSON {
		t.Fatalf("unexpected JSON results: got %s want %s", encoded, expectedJSON)
	}

	decrypted, err := client.Decrypt([]string{"aGVsbG8="}, nil, []string{"base64($pass)"}, Affixes{})
	if err != nil {
		t.Fatal(err)
	}
	expectedDecrypted := []Result{{
		Hash:      "aGVsbG8=",
		Algorithm: "base64($pass)",
		Type:      "encrypt",
		Plaintext: "hello",
	}}
	if !reflect.DeepEqual(decrypted, expectedDecrypted) {
		t.Fatalf("unexpected decryption results: got %#v want %#v", decrypted, expectedDecrypted)
	}
}

// TestInMemoryCrackUsesCandidates checks real-time value-based hash recovery.
func TestInMemoryCrackUsesCandidates(t *testing.T) {
	client := newTestClient(t)
	got, err := client.Crack([]string{"5d41402abc4b2a76b9719d911017c592"}, []string{"wrong", "hello"}, nil, []string{"md5($pass)"}, Affixes{})
	if err != nil {
		t.Fatal(err)
	}
	expected := []Result{{
		Hash:      "5d41402abc4b2a76b9719d911017c592",
		Algorithm: "md5($pass)",
		Type:      "static",
		Plaintext: "hello",
	}}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("unexpected crack results: got %#v want %#v", got, expected)
	}

	saltedHash := md5.Sum([]byte("hellosalt"))
	salted, err := client.Crack([]string{hex.EncodeToString(saltedHash[:])}, []string{"hello"}, []string{"salt"}, []string{"md5($pass.$salt)"}, Affixes{})
	if err != nil {
		t.Fatal(err)
	}
	expectedSalted := []Result{{
		Hash:      hex.EncodeToString(saltedHash[:]),
		Algorithm: "md5($pass.$salt)",
		Type:      "static",
		Plaintext: "hello",
		Salt:      "salt",
	}}
	if !reflect.DeepEqual(salted, expectedSalted) {
		t.Fatalf("unexpected salted crack results: got %#v want %#v", salted, expectedSalted)
	}
}

// TestCrackPreservesPlaintextWhitespace checks that in-memory candidates are not line-trimmed.
func TestCrackPreservesPlaintextWhitespace(t *testing.T) {
	client := newTestClient(t)
	plaintext := " hello "
	digest := md5.Sum([]byte(plaintext))
	got, err := client.Crack([]string{hex.EncodeToString(digest[:])}, []string{plaintext}, nil, []string{"md5($pass)"}, Affixes{})
	if err != nil {
		t.Fatal(err)
	}
	expected := []Result{{
		Hash:      hex.EncodeToString(digest[:]),
		Algorithm: "md5($pass)",
		Type:      "static",
		Plaintext: plaintext,
	}}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("unexpected whitespace candidate results: got %#v want %#v", got, expected)
	}
}

// TestCrackParsesSaltedTargetStrings checks hash:salt target input parsing.
func TestCrackParsesSaltedTargetStrings(t *testing.T) {
	client := newTestClient(t)
	digest := md5.Sum([]byte("hellosalt"))
	hash := hex.EncodeToString(digest[:])
	got, err := client.Crack([]string{hash + ":salt"}, []string{"hello"}, nil, []string{"md5($pass.$salt)"}, Affixes{})
	if err != nil {
		t.Fatal(err)
	}
	expected := []Result{{
		Hash:      hash,
		Algorithm: "md5($pass.$salt)",
		Type:      "static",
		Plaintext: "hello",
		Salt:      "salt",
	}}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("unexpected salted target results: got %#v want %#v", got, expected)
	}
}

// TestOperationAffixesApplyPerCall checks affixes are isolated to each operation.
func TestOperationAffixesApplyPerCall(t *testing.T) {
	client := newTestClient(t)
	affixes := Affixes{PassPrefix: "P-", PassSuffix: "-S", SaltPrefix: "X-", SaltSuffix: "-Y"}
	plaintext := "hello"
	secret := "salt"
	digest := md5.Sum([]byte("P-" + plaintext + "-S" + "X-" + secret + "-Y"))
	hash := hex.EncodeToString(digest[:])

	desAlgorithm := &des.CrmebAdminAlgo{}
	expectedCiphertext, err := desAlgorithm.Seal("P-"+plaintext+"-S", "X-"+secret+"-Y")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := client.Encrypt([]string{plaintext}, []string{secret}, []string{"des_crmeb_admin"}, affixes)
	if err != nil {
		t.Fatal(err)
	}
	if len(encrypted) != 1 || encrypted[0].Hash != expectedCiphertext || encrypted[0].Plaintext != plaintext || encrypted[0].Salt != secret {
		t.Fatalf("unexpected affixed encryption result: %#v", encrypted)
	}

	cracked, err := client.Crack([]string{hash}, []string{plaintext}, []string{secret}, []string{"md5($pass.$salt)"}, affixes)
	if err != nil {
		t.Fatal(err)
	}
	wantCracked := []Result{{Hash: hash, Algorithm: "md5($pass.$salt)", Type: "static", Plaintext: plaintext, Salt: secret}}
	wantCracked[0].Plaintext = "P-hello-S"
	if !reflect.DeepEqual(cracked, wantCracked) {
		t.Fatalf("unexpected affixed crack result: got %#v want %#v", cracked, wantCracked)
	}

	plainHash := md5.Sum([]byte(plaintext))
	withoutAffixes, err := client.Crack([]string{hex.EncodeToString(plainHash[:])}, []string{plaintext}, nil, []string{"md5($pass)"}, Affixes{})
	if err != nil {
		t.Fatal(err)
	}
	if len(withoutAffixes) != 1 || withoutAffixes[0].Plaintext != plaintext {
		t.Fatalf("previous operation affixes leaked: %#v", withoutAffixes)
	}

	const ciphertext = "Ls34Pql552iTH1xkO+dy1OWAQx0GdmK5"
	decryptSecret := "m"
	decryptAffixes := Affixes{SaltPrefix: "ad", SaltSuffix: "in"}
	decrypted, err := client.Decrypt([]string{ciphertext}, []string{decryptSecret}, []string{"des_crmeb_admin"}, decryptAffixes)
	if err != nil {
		t.Fatal(err)
	}
	if len(decrypted) != 1 || decrypted[0].Plaintext != "Y9jmpE.7ERnid4BG" || decrypted[0].Salt != decryptSecret {
		t.Fatalf("unexpected affixed decrypt result: %#v", decrypted)
	}
}

// TestConcurrentOperationsKeepAffixesIsolated checks simultaneous calls share no affix state.
func TestConcurrentOperationsKeepAffixesIsolated(t *testing.T) {
	client := newTestClient(t)
	algorithm := &des.CrmebAdminAlgo{}
	configs := []struct {
		affixes Affixes
		secret  string
	}{
		{affixes: Affixes{PassPrefix: "one-", SaltPrefix: "key-"}, secret: "first"},
		{affixes: Affixes{PassSuffix: "-two", SaltSuffix: "-key"}, secret: "second"},
	}
	var wg sync.WaitGroup
	for _, config := range configs {
		config := config
		wantHash, err := algorithm.Seal(config.affixes.PassPrefix+"plain"+config.affixes.PassSuffix, config.affixes.SaltPrefix+config.secret+config.affixes.SaltSuffix)
		if err != nil {
			t.Fatal(err)
		}
		for range 10 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, err := client.Encrypt([]string{"plain"}, []string{config.secret}, []string{"des_crmeb_admin"}, config.affixes)
				if err != nil {
					t.Errorf("encrypt with affixes: %v", err)
					return
				}
				if len(got) != 1 || got[0].Hash != wantHash {
					t.Errorf("concurrent affixes changed result: %#v, want hash %q", got, wantHash)
				}
			}()
		}
	}
	wg.Wait()
}

// TestInvalidRequestsChecksInputAndAlgorithmErrors checks exported operation validation.
func TestInvalidRequestsChecksInputAndAlgorithmErrors(t *testing.T) {
	client := newTestClient(t)
	tests := []struct {
		name string
		run  func() error
	}{
		{name: "empty encrypt values", run: func() error { _, err := client.Encrypt(nil, nil, nil, Affixes{}); return err }},
		{name: "unknown encrypt algorithm", run: func() error {
			_, err := client.Encrypt([]string{"hello"}, nil, []string{"missing"}, Affixes{})
			return err
		}},
		{name: "empty crack values", run: func() error { _, err := client.Crack(nil, nil, nil, nil, Affixes{}); return err }},
		{name: "crack candidate with line break", run: func() error {
			_, err := client.Crack([]string{"hash"}, []string{"hello\nworld"}, nil, nil, Affixes{})
			return err
		}},
		{name: "empty crack target", run: func() error {
			_, err := client.Crack([]string{""}, []string{"hello"}, nil, nil, Affixes{})
			return err
		}},
		{name: "missing crack target", run: func() error {
			_, err := client.Crack(nil, []string{"hello"}, nil, nil, Affixes{})
			return err
		}},
		{name: "unknown crack algorithm", run: func() error {
			_, err := client.Crack([]string{"hash"}, []string{"hello"}, nil, []string{"missing"}, Affixes{})
			return err
		}},
		{name: "non-hash crack algorithm", run: func() error {
			_, err := client.Crack([]string{"hash"}, []string{"hello"}, nil, []string{"base64($pass)"}, Affixes{})
			return err
		}},
		{name: "empty decrypt target", run: func() error {
			_, err := client.Decrypt([]string{""}, nil, nil, Affixes{})
			return err
		}},
		{name: "missing decrypt target", run: func() error {
			_, err := client.Decrypt(nil, nil, nil, Affixes{})
			return err
		}},
		{name: "non-reversible decrypt algorithm", run: func() error {
			_, err := client.Decrypt([]string{"hash"}, nil, []string{"md5($pass)"}, Affixes{})
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); err == nil {
				t.Fatal("expected request to fail")
			}
		})
	}
}

// newTestClient creates a client whose runtime files stay inside the test directory.
func newTestClient(t *testing.T) *Client {
	t.Helper()
	root := t.TempDir()
	client, err := NewClient(Config{
		Workers:     1,
		DataDir:     filepath.Join(root, "data"),
		RunCacheDir: filepath.Join(root, "cache"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// contains reports whether values includes expected.
func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
