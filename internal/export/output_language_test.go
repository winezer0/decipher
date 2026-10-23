package export

import (
	"decipher/internal/cracker"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

func TestExportOpenErrorsAreEnglish(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "output.csv")
	tests := []struct {
		name string
		run  func() error
	}{
		{"results", func() error { return ExportCSV(path, nil, true) }},
		{"failures", func() error {
			return ExportFailureCSV(path, map[string]cracker.HashSaltTarget{"hash": {Hash: "hash"}}, true)
		}},
		{"identification", func() error {
			return ExportIdentCSV(path, []cracker.IdentResult{{Hash: "hash"}}, true)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if err == nil || !strings.HasPrefix(err.Error(), "open file failed:") {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, r := range err.Error() {
				if unicode.Is(unicode.Han, r) {
					t.Fatalf("error contains non-English text: %v", err)
				}
			}
		})
	}
}
