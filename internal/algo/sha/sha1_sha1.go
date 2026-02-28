package sha

import (
	"decipher/internal/algo/types"
)

type SHA1DoubleAlgo struct{}

func (a *SHA1DoubleAlgo) Name() string { return "sha1(sha1($pass))" }

func (a *SHA1DoubleAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

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

func (a *SHA1DoubleAlgo) NeedsPrecomputation() bool { return true }
