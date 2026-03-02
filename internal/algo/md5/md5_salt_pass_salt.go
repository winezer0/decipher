package md5

import (
	"decipher/internal/algo/types"
)

type MD5SaltPassSaltAlgo struct{}

func (a *MD5SaltPassSaltAlgo) Name() string { return "md5($salt.$pass.$salt)" }

func (a *MD5SaltPassSaltAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5SaltPassSaltAlgo) Seal(plaintext, secret string) (string, error) {
	return md5Hex(secret + plaintext + secret), nil
}

func (a *MD5SaltPassSaltAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5SaltPassSaltAlgo) NeedAddToPredb() bool { return true }
