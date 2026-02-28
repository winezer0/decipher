package ntlm

import (
	"decipher/internal/algo/types"
	"encoding/hex"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

type NTLMAlgo struct{}

func (a *NTLMAlgo) Name() string { return "ntlm" }

func (a *NTLMAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *NTLMAlgo) Seal(plaintext, secret string) (string, error) {
	u16 := utf16.Encode([]rune(plaintext))
	b := make([]byte, len(u16)*2)
	for i, v := range u16 {
		b[i*2] = byte(v)
		b[i*2+1] = byte(v >> 8)
	}

	h := md4.New()
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (a *NTLMAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, "")
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *NTLMAlgo) NeedsPrecomputation() bool { return true }
