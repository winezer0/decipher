package md5

import (
	"decipher/internal/algo/types"
)

type MD5PassSaltAlgo struct{}

func (a *MD5PassSaltAlgo) Name() string { return "md5($pass.$salt)" }

func (a *MD5PassSaltAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5PassSaltAlgo) Seal(plaintext, secret string) (string, error) {
	return md5Hex(plaintext + secret), nil
}

func (a *MD5PassSaltAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5PassSaltAlgo) NeedsPrecomputation() bool { return true }
