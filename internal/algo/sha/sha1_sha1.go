package sha

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
)

type SHA1DoubleAlgo struct{}

func (a *SHA1DoubleAlgo) Name() string { return "sha1(sha1($pass))" }

func (a *SHA1DoubleAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA1DoubleAlgo) NeedSalt() bool { return false }

func (a *SHA1DoubleAlgo) Seal(plaintext, secret string) (string, error) {
	return sha1Hex(sha1Hex(plaintext)), nil
}

func (a *SHA1DoubleAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, "")
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA1DoubleAlgo) NeedAddToPredb() bool { return true }

func (a *SHA1DoubleAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 40)
}
