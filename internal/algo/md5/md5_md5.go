package md5

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
)

type MD5DoubleAlgo struct{}

func (a *MD5DoubleAlgo) Name() string { return "md5(md5($pass))" }

func (a *MD5DoubleAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5DoubleAlgo) NeedSalt() bool { return false }

func (a *MD5DoubleAlgo) Seal(plaintext, secret string) (string, error) {
	return md5Hex(md5Hex(plaintext)), nil
}

func (a *MD5DoubleAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, "")
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5DoubleAlgo) NeedAddToPredb() bool { return true }

func (a *MD5DoubleAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
