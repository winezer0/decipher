package sha

import (
	"crypto/sha256"
	"decipher/internal/algo/types"
	"encoding/hex"
	"io"
)

type SHA256Algo struct{}

func (a *SHA256Algo) Name() string { return "sha256" }

func (a *SHA256Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA256Algo) Seal(plaintext, secret string) (string, error) {
	return sha256Hex(plaintext), nil
}

func (a *SHA256Algo) Recover(token, secret, candidatePlain string) (string, error) {
	computed := sha256Hex(candidatePlain)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA256Algo) NeedsPrecomputation() bool { return true }

func sha256Hex(s string) string {
	h := sha256.New()
	io.WriteString(h, s)
	return hex.EncodeToString(h.Sum(nil))
}
