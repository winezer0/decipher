package sha

import (
	"crypto/sha512"
	"decipher/internal/algo/types"
	"encoding/hex"
	"io"
)

type SHA512Algo struct{}

func (a *SHA512Algo) Name() string { return "sha512" }

func (a *SHA512Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA512Algo) Seal(plaintext, secret string) (string, error) {
	h := sha512.New()
	io.WriteString(h, plaintext)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (a *SHA512Algo) Recover(token, secret, candidatePlain string) (string, error) {
	h := sha512.New()
	io.WriteString(h, candidatePlain)
	computed := hex.EncodeToString(h.Sum(nil))
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA512Algo) NeedsPrecomputation() bool { return true }
