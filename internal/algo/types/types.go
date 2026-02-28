package types

import (
	"errors"
	"unicode/utf8"
)

type AlgoType string

const (
	AlgoIsStatic  AlgoType = "static"
	AlgoIsDynamic AlgoType = "dynamic"
	AlgoIsEncrypt AlgoType = "encrypt"
)

var (
	ErrVerificationFailed = errors.New("verification failed: plaintext does not match hash")
	ErrDecryptionFailed   = errors.New("decryption failed: invalid key or corrupted data")
	ErrInvalidInput       = errors.New("invalid input parameters")
)

func IsPrintableUTF8(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}

	for _, b := range data {
		if b < 32 && b != '\t' && b != '\n' && b != '\r' {
			return false
		}
		if b > 126 && b < 128 {
			return false
		}
	}
	return true
}
