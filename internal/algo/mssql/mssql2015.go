package mssql

import (
	"crypto/sha1"
	"decipher/internal/algo/types"
	"encoding/hex"
	"fmt"
	"unicode/utf16"
)

type MSSQL2015Algo struct{}

func (a *MSSQL2015Algo) Name() string { return "MSSQL2015" }

func (a *MSSQL2015Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func parseMSSQLSalt(secret string) []byte {
	if len(secret) == 0 {
		return make([]byte, 4)
	}

	saltHex := secret
	if len(saltHex)%2 != 0 {
		saltHex = saltHex + "0"
	}
	if len(saltHex) < 8 {
		for len(saltHex) < 8 {
			saltHex = saltHex + "00"
		}
	}

	decoded, err := hex.DecodeString(saltHex[:8])
	if err != nil {
		saltBytes := make([]byte, 4)
		copy(saltBytes, []byte(secret))
		for i := len([]byte(secret)); i < 4; i++ {
			saltBytes[i] = 0x00
		}
		return saltBytes
	}

	return decoded
}

func (a *MSSQL2015Algo) Seal(plaintext, secret string) (string, error) {
	saltBytes := parseMSSQLSalt(secret)

	u16 := utf16.Encode([]rune(plaintext))
	passBytes := make([]byte, len(u16)*2)
	for i, v := range u16 {
		passBytes[i*2] = byte(v)
		passBytes[i*2+1] = byte(v >> 8)
	}

	h := sha1.New()
	h.Write(passBytes)
	h.Write(saltBytes)
	hash := h.Sum(nil)

	return fmt.Sprintf("0x0100%s%s", hex.EncodeToString(saltBytes), hex.EncodeToString(hash)), nil
}

func (a *MSSQL2015Algo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MSSQL2015Algo) NeedsPrecomputation() bool { return true }
