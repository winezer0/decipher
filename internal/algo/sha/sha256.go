package sha

import (
	"crypto/sha256"
	"github.com/winezer0/decipher/internal/algo/types"
	"github.com/winezer0/decipher/internal/ident"
)

type SHA256Algo struct{}

func (a *SHA256Algo) Name() string { return "sha256($pass)" }

func (a *SHA256Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA256Algo) NeedSalt() bool { return false }

func (a *SHA256Algo) Seal(plaintext, secret string) (string, error) {
	return sha256Hex(plaintext), nil
}

func (a *SHA256Algo) Recover(token, secret, candidatePlain string) (string, error) {
	if sha256Matches(token, sha256.Sum256([]byte(candidatePlain))) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA256Algo) NeedAddToPredb() bool { return true }

func (a *SHA256Algo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 64)
}
