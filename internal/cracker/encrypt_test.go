package cracker

import (
	"decipher/internal/algo"
	"decipher/internal/algo/md5"
	"sort"
	"strings"
	"testing"
)

func TestRunEncryption(t *testing.T) {
	md5SaltPassAlgo := &md5.MD5SaltPassAlgo{}

	tests := []struct {
		name     string
		texts    []string
		salts    []string
		algos    []algo.Algorithm
		expected []string
	}{
		{
			name:  "Single text, no salt",
			texts: []string{"hello"},
			salts: []string{},
			algos: []algo.Algorithm{md5SaltPassAlgo},
			expected: []string{
				"md5($salt.$pass):5d41402abc4b2a76b9719d911017c592::hello",
			},
		},
		{
			name:  "Single text, single salt",
			texts: []string{"hello"},
			salts: []string{"salt1"},
			algos: []algo.Algorithm{md5SaltPassAlgo},
			expected: []string{
				"md5($salt.$pass):95a2e8514b40b95ef41fb464a6e382ee:salt1:hello",
			},
		},
		{
			name:  "Multiple texts, multiple salts",
			texts: []string{"t1", "t2"},
			salts: []string{"s1", "s2"},
			algos: []algo.Algorithm{md5SaltPassAlgo},
			expected: []string{
				"md5($salt.$pass):10df6e5eff60de6558e080133ce7039a:s1:t1",
				"md5($salt.$pass):5551cfd3f7afec0c82711ac1dd5e09dd:s2:t1",
				"md5($salt.$pass):4e5ce80787bdc9c2967bc233d72c3b18:s1:t2",
				"md5($salt.$pass):38c3684c6afc75caef88c18f694697f5:s2:t2",
			},
		},
	}

	engine := NewEngine(1, "cache_dir", "")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := engine.RunEncrypt(tt.texts, tt.salts, tt.algos)

			if len(lines) != len(tt.expected) {
				t.Errorf("Expected %d lines, got %d. Output:\n%v", len(tt.expected), len(lines), lines)
			}

			sort.Strings(lines)
			sort.Strings(tt.expected)

			for i, line := range lines {
				if i >= len(tt.expected) {
					break
				}
				if strings.TrimSpace(line) != strings.TrimSpace(tt.expected[i]) {
					t.Errorf("Line %d: expected %q, got %q", i, tt.expected[i], line)
				}
			}
		})
	}
}
