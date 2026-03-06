package sha

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
)

type SHA256Algo struct{}

func (a *SHA256Algo) Name() string { return "sha256" }

func (a *SHA256Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA256Algo) NeedSalt() bool { return false }

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

func (a *SHA256Algo) NeedAddToPredb() bool { return true }

func (a *SHA256Algo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 64)
}
