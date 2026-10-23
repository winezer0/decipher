// Package sdk exposes decipher operations to Go programs.
package sdk

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/winezer0/decipher/internal/algo"
	"github.com/winezer0/decipher/internal/cracker"
)

// Config contains runtime settings for an SDK client.
type Config struct {
	Workers     int
	DataDir     string
	RunCacheDir string
}

// Affixes are applied per operation; decryption uses only salt fields on candidate keys.
type Affixes struct {
	PassPrefix string `json:"pass_prefix,omitempty"`
	PassSuffix string `json:"pass_suffix,omitempty"`
	SaltPrefix string `json:"salt_prefix,omitempty"`
	SaltSuffix string `json:"salt_suffix,omitempty"`
}

// Client exposes fine-grained decipher operations to Go programs.
type Client struct {
	engine *cracker.Engine
}

// AlgorithmInfo describes an algorithm available to the client.
type AlgorithmInfo struct {
	Name                string `json:"name"`
	Type                string `json:"type"`
	NeedsSalt           bool   `json:"needs_salt"`
	NeedsPrecomputation bool   `json:"needs_precomputation"`
}

// Identification contains the algorithms that recognize a hash.
type Identification struct {
	Hash       string   `json:"hash"`
	Algorithms []string `json:"algorithms"`
}

// Result contains a recovered plaintext and the algorithm details.
type Result struct {
	Hash      string `json:"hash"`
	Algorithm string `json:"algorithm"`
	Type      string `json:"type"`
	Plaintext string `json:"plaintext"`
	Salt      string `json:"salt"`
}

// EncryptionResult contains an algorithm output and its source values.
type EncryptionResult struct {
	Algorithm string `json:"algorithm"`
	Hash      string `json:"hash"`
	Salt      string `json:"salt"`
	Plaintext string `json:"plaintext"`
}

// NewClient creates a client and initializes its runtime directories.
func NewClient(config Config) (*Client, error) {
	if config.Workers < 0 {
		return nil, errors.New("workers cannot be negative")
	}
	if config.DataDir == "" || config.RunCacheDir == "" {
		baseDir, err := defaultDataDir()
		if err != nil {
			return nil, err
		}
		if config.DataDir == "" {
			config.DataDir = filepath.Join(baseDir, "data")
		}
		if config.RunCacheDir == "" {
			config.RunCacheDir = filepath.Join(baseDir, "cache")
		}
	}
	for _, path := range []string{config.DataDir, config.RunCacheDir} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return nil, fmt.Errorf("create SDK data directory %s: %w", path, err)
		}
	}
	engine := cracker.NewEngine(config.Workers, config.DataDir, config.RunCacheDir)
	if err := engine.InitBuiltinDicts(); err != nil {
		return nil, fmt.Errorf("initialize built-in dictionaries: %w", err)
	}
	return &Client{engine: engine}, nil
}

// ListAlgorithms returns metadata for all supported algorithms.
func (c *Client) ListAlgorithms() []AlgorithmInfo {
	algorithms := algo.GetAllAlgorithms()
	result := make([]AlgorithmInfo, 0, len(algorithms))
	for _, algorithm := range algorithms {
		result = append(result, AlgorithmInfo{
			Name:                algorithm.Name(),
			Type:                string(algorithm.GetAlgoType()),
			NeedsSalt:           algorithm.NeedSalt(),
			NeedsPrecomputation: algorithm.NeedAddToPredb(),
		})
	}
	return result
}

// Identify matches hash strings against the supported algorithms.
func (c *Client) Identify(hashes []string) []Identification {
	all := algo.GetAllAlgorithms()
	results := make([]Identification, 0, len(hashes))
	for _, value := range hashes {
		hash := strings.TrimSpace(value)
		if hash == "" || strings.HasPrefix(hash, "#") {
			continue
		}
		if first, _, ok := strings.Cut(hash, ":"); ok {
			hash = first
		}
		matched := make([]string, 0)
		for _, algorithm := range all {
			if algorithm.Identify(hash) {
				matched = append(matched, algorithm.Name())
			}
		}
		results = append(results, Identification{Hash: hash, Algorithms: matched})
	}
	return results
}

// Encrypt computes algorithms for in-memory plaintext and salt lists using per-call affixes.
func (c *Client) Encrypt(plaintexts, secrets, algorithms []string, affixes Affixes) ([]EncryptionResult, error) {
	if len(plaintexts) == 0 {
		return nil, errors.New("at least one plaintext value is required")
	}
	selected, err := selectAlgorithms(algorithms)
	if err != nil {
		return nil, err
	}
	selected = algo.FilterEncryptAlgorithms(selected)
	if len(selected) == 0 {
		return nil, errors.New("no encryption algorithms selected")
	}
	results := make([]EncryptionResult, 0)
	engine := c.engine.WithAffixes(affixes.PassPrefix, affixes.PassSuffix, affixes.SaltPrefix, affixes.SaltSuffix)
	err = engine.RunEncryptValuesStream(plaintexts, secrets, selected, func(result cracker.EncryptResult) error {
		results = append(results, EncryptionResult{
			Algorithm: result.Algorithm,
			Hash:      result.Hash,
			Salt:      result.Salt,
			Plaintext: result.Plaintext,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

// Crack recovers hashes in real time from in-memory candidate lists using per-call affixes.
func (c *Client) Crack(targets, plaintexts, secrets, algorithms []string, affixes Affixes) ([]Result, error) {
	if err := validatePlaintexts(plaintexts); err != nil {
		return nil, err
	}
	parsedTargets, err := normalizeTargets(targets)
	if err != nil {
		return nil, err
	}
	selected, err := selectAlgorithms(algorithms)
	if err != nil {
		return nil, err
	}
	selected = append(algo.FilterStaticAlgorithms(selected), algo.FilterDynamicAlgorithms(selected)...)
	if len(selected) == 0 {
		return nil, errors.New("no hash algorithms selected")
	}
	engine := c.engine.WithAffixes(affixes.PassPrefix, affixes.PassSuffix, affixes.SaltPrefix, affixes.SaltSuffix)
	results := engine.RunHashCrackValues(parsedTargets, plaintexts, secrets, selected)
	return convertResults(results), nil
}

// CrackWithBuiltinDictionaries cracks targets in real time using persisted built-in dictionaries and per-call affixes.
func (c *Client) CrackWithBuiltinDictionaries(targets, algorithms []string, affixes Affixes) ([]Result, error) {
	parsedTargets, err := normalizeTargets(targets)
	if err != nil {
		return nil, err
	}
	selected, err := selectAlgorithms(algorithms)
	if err != nil {
		return nil, err
	}
	selected = append(algo.FilterStaticAlgorithms(selected), algo.FilterDynamicAlgorithms(selected)...)
	if len(selected) == 0 {
		return nil, errors.New("no hash algorithms selected")
	}
	engine := c.engine.WithAffixes(affixes.PassPrefix, affixes.PassSuffix, affixes.SaltPrefix, affixes.SaltSuffix)
	results := engine.RunHashCrack(
		parsedTargets,
		[]string{c.engine.GetBuiltinPlainPath()},
		[]string{c.engine.GetBuiltinSaltPath()},
		selected,
	)
	return convertResults(results), nil
}

// Decrypt tries reversible algorithms against in-memory targets and secrets using salt affixes on keys.
func (c *Client) Decrypt(targets, secrets, algorithms []string, affixes Affixes) ([]Result, error) {
	parsedTargets, err := normalizeTargets(targets)
	if err != nil {
		return nil, err
	}
	selected, err := selectAlgorithms(algorithms)
	if err != nil {
		return nil, err
	}
	selected = algo.FilterEncryptAlgorithms(selected)
	if len(selected) == 0 {
		return nil, errors.New("no reversible algorithms selected")
	}
	engine := c.engine.WithAffixes("", "", affixes.SaltPrefix, affixes.SaltSuffix)
	return convertResults(engine.RunDecryptValues(parsedTargets, secrets, selected)), nil
}

// InitBuiltinDictionaries initializes the persistent built-in plaintext and salt dictionaries.
func (c *Client) InitBuiltinDictionaries() error {
	return c.engine.InitBuiltinDicts()
}

// AddPlaintexts appends in-memory plaintext values to the persistent built-in dictionary.
func (c *Client) AddPlaintexts(plaintexts []string) error {
	return appendValues(c.engine.GetBuiltinPlainPath(), plaintexts)
}

// AddSecrets appends in-memory salt values to the persistent built-in dictionary.
func (c *Client) AddSecrets(secrets []string) error {
	return appendValues(c.engine.GetBuiltinSaltPath(), secrets)
}

// defaultDataDir resolves the per-user directory for SDK runtime data.
func defaultDataDir() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolve user cache directory: %w", err)
	}
	return filepath.Join(cacheDir, "decipher"), nil
}

// selectAlgorithms resolves exact public algorithm names.
func selectAlgorithms(names []string) ([]algo.Algorithm, error) {
	if len(names) == 0 {
		return algo.GetAllAlgorithms(), nil
	}
	selected := make([]algo.Algorithm, 0, len(names))
	for _, name := range names {
		algorithm := algo.GetAlgorithmByName(name)
		if algorithm == nil {
			return nil, fmt.Errorf("unknown algorithm %q", name)
		}
		selected = append(selected, algorithm)
	}
	return selected, nil
}

// normalizeTargets parses hash and optional salt values into engine targets.
func normalizeTargets(input []string) ([]cracker.HashSaltTarget, error) {
	if len(input) == 0 {
		return nil, errors.New("at least one target is required")
	}
	targets := make([]cracker.HashSaltTarget, 0, len(input))
	for _, value := range input {
		line := strings.TrimSpace(value)
		hash, salt, _, err := cracker.ParseHashLine(line, ":")
		if err != nil {
			return nil, err
		}
		hash = strings.TrimSpace(hash)
		if hash == "" {
			return nil, errors.New("target hash cannot be empty")
		}
		targets = append(targets, cracker.HashSaltTarget{Hash: hash, Salt: salt})
	}
	return targets, nil
}

// validatePlaintexts checks candidate strings can be represented as individual values.
func validatePlaintexts(plaintexts []string) error {
	if len(plaintexts) == 0 {
		return errors.New("at least one plaintext value is required")
	}
	for _, plaintext := range plaintexts {
		if plaintext == "" {
			return errors.New("plaintext values cannot be empty")
		}
		if strings.ContainsAny(plaintext, "\r\n") {
			return errors.New("plaintext values cannot contain line breaks")
		}
	}
	return nil
}

// appendValues appends newline-delimited values without interpreting them as paths.
func appendValues(path string, values []string) error {
	if len(values) == 0 {
		return nil
	}
	for _, value := range values {
		if value == "" {
			return errors.New("dictionary values cannot be empty")
		}
		if strings.ContainsAny(value, "\r\n") {
			return errors.New("dictionary values cannot contain line breaks")
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("open built-in dictionary %s: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat built-in dictionary %s: %w", path, err)
	}
	if info.Size() > 0 {
		var last [1]byte
		if _, err := f.ReadAt(last[:], info.Size()-1); err != nil {
			return fmt.Errorf("read built-in dictionary %s: %w", path, err)
		}
		if last[0] != '\n' {
			if _, err := f.WriteString("\n"); err != nil {
				return fmt.Errorf("separate built-in dictionary values: %w", err)
			}
		}
	}
	var content strings.Builder
	for _, value := range values {
		content.WriteString(value)
		content.WriteByte('\n')
	}
	if _, err := f.WriteString(content.String()); err != nil {
		return fmt.Errorf("append built-in dictionary values: %w", err)
	}
	return nil
}

// convertResults maps engine results to the public SDK response type.
func convertResults(input []cracker.CrackerResult) []Result {
	results := make([]Result, 0, len(input))
	for _, result := range input {
		results = append(results, Result{
			Hash:      result.Hash,
			Algorithm: result.Algorithm,
			Type:      result.AlgoType,
			Plaintext: result.Plaintext,
			Salt:      result.Salt,
		})
	}
	return results
}
