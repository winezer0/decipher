package cracker

import (
	"strings"
	"testing"
)

func TestLoadBuiltinPlainEntries(t *testing.T) {
	entries := loadBuiltinPlainsEntries()
	if entries == nil {
		t.Fatalf("entries is nil")
	}
	// Allow empty datasets, but ensure all are trimmed and non-empty
	for i, s := range entries {
		if strings.TrimSpace(s) == "" {
			t.Fatalf("entry %d is empty after trim", i)
		}
		if s != strings.TrimSpace(s) {
			t.Fatalf("entry %d not trimmed", i)
		}
	}
}
