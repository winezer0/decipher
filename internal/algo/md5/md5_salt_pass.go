package md5

import (
	"decipher/internal/algo/types"
)

type MD5SaltPassAlgo struct{}

func (a *MD5SaltPassAlgo) Name() string { return "md5($salt.$pass)" }

func (a *MD5SaltPassAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5SaltPassAlgo) Seal(plaintext, secret string) (string, error) {
	return md5Hex(secret + plaintext), nil
}

func (a *MD5SaltPassAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5SaltPassAlgo) NeedsPrecomputation() bool { return true }
