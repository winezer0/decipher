package cracker

import (
	"io"
	"os"
	"testing"
)

func TestDictSource(t *testing.T) {
	t.Run("FileProvider", func(t *testing.T) {
		tempFile, err := os.CreateTemp("", "test_*.txt")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer os.Remove(tempFile.Name())

		if _, err := tempFile.WriteString("test content\n"); err != nil {
			t.Fatalf("Failed to write temp file: %v", err)
		}
		tempFile.Close()

		source := dictSource{
			Name: "test",
			Provider: func() (io.ReadSeeker, error) {
				f, err := os.Open(tempFile.Name())
				if err != nil {
					return nil, err
				}
				return f, nil
			},
		}

		reader, err := source.Provider()
		if err != nil {
			t.Fatalf("Provider failed: %v", err)
		}
		if reader == nil {
			t.Error("Provider returned nil reader")
		}

		if closer, ok := reader.(io.Closer); ok {
			closer.Close()
		}
	})
}
