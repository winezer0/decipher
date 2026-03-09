package sha

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
)

type SHA256PassSaltAlgo struct{}

func (a *SHA256PassSaltAlgo) Name() string { return "sha256($pass.$salt)" }

func (a *SHA256PassSaltAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA256PassSaltAlgo) NeedSalt() bool { return true }

func (a *SHA256PassSaltAlgo) Seal(plaintext, secret string) (string, error) {
	return sha256Hex(plaintext + secret), nil
}

func (a *SHA256PassSaltAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed := sha256Hex(candidatePlain + secret)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA256PassSaltAlgo) NeedAddToPredb() bool { return false }

func (a *SHA256PassSaltAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 64)
}
