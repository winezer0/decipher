package sha

import (
	"decipher/internal/algo/types"
)

type SHA512PassSaltAlgo struct{}

func (a *SHA512PassSaltAlgo) Name() string { return "sha512($pass.$salt)" }

func (a *SHA512PassSaltAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA512PassSaltAlgo) Seal(plaintext, secret string) (string, error) {
	return sha512Hex(plaintext + secret), nil
}

func (a *SHA512PassSaltAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed := sha512Hex(candidatePlain + secret)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA512PassSaltAlgo) NeedsPrecomputation() bool { return true }
