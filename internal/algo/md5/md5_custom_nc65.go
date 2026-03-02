package md5

import (
	"decipher/internal/algo/types"
)

type MD5CustomNc65Algo struct{}

func (a *MD5CustomNc65Algo) Name() string { return "md5_custom_nc65" }

func (a *MD5CustomNc65Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5CustomNc65Algo) Seal(plaintext, secret string) (string, error) {
	return "U_U++--V" + md5Hex(secret+plaintext), nil
}

func (a *MD5CustomNc65Algo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5CustomNc65Algo) NeedAddToPredb() bool { return true }
