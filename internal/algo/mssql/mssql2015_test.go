package mssql

import (
	"bytes"
	"testing"
)

func TestParseMSSQLSalt(t *testing.T) {
	tests := []struct {
		name     string
		secret   string
		expected []byte
	}{
		{
			name:     "Empty salt",
			secret:   "",
			expected: []byte{0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "Valid 8-char hex",
			secret:   "66666000",
			expected: []byte{0x66, 0x66, 0x60, 0x00},
		},
		{
			name:     "5-char hex padded",
			secret:   "66666",
			expected: []byte{0x66, 0x66, 0x60, 0x00},
		},
		{
			name:     "4-char hex padded",
			secret:   "abcd",
			expected: []byte{0xab, 0xcd, 0x00, 0x00},
		},
		{
			name:     "Invalid hex fallback",
			secret:   "test",
			expected: []byte{'t', 'e', 's', 't'},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMSSQLSalt(tt.secret)
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("parseMSSQLSalt(%q) = %v, want %v", tt.secret, got, tt.expected)
			}
		})
	}
}

func TestMSSQL2015Algo_Seal_EmptySalt(t *testing.T) {
	algo := &MSSQL2015Algo{}
	want := "0x010000000000a759cb9caac46bd28de0b3e2c382753deb0f83df"
	got, err := algo.Seal("123456", "00000000")
	if err != nil {
		t.Errorf("MSSQL2015Algo.Seal() error = %v", err)
		return
	}
	if got != want {
		t.Errorf("MSSQL2015Algo.Seal(123456, 00000000) = %v, want %v", got, want)
	}
}

func TestMSSQL2015Algo_Seal_WithSalt(t *testing.T) {
	algo := &MSSQL2015Algo{}
	want := "0x0100666660002712815c5906d66b8def6bff96296f973c46cf2d"
	got, err := algo.Seal("123456", "66666000")
	if err != nil {
		t.Errorf("MSSQL2015Algo.Seal() error = %v", err)
		return
	}
	if got != want {
		t.Errorf("MSSQL2015Algo.Seal(123456, 66666000) = %v, want %v", got, want)
	}
}

func TestMSSQL2015Algo_Seal_PaddedSalt(t *testing.T) {
	algo := &MSSQL2015Algo{}
	want := "0x0100666660002712815c5906d66b8def6bff96296f973c46cf2d"
	got, err := algo.Seal("123456", "66666")
	if err != nil {
		t.Errorf("MSSQL2015Algo.Seal() error = %v", err)
		return
	}
	if got != want {
		t.Errorf("MSSQL2015Algo.Seal(123456, 66666) = %v, want %v", got, want)
	}
}
