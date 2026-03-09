package md5

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
)

type MD5CustomMssAlgo struct{}

func (a *MD5CustomMssAlgo) Name() string { return "md5_custom_mss" }

func (a *MD5CustomMssAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5CustomMssAlgo) NeedSalt() bool { return false }

func (a *MD5CustomMssAlgo) Seal(plaintext, secret string) (string, error) {
	inner := md5Hex(md5Hex(plaintext) + "pwd@2019")
	return md5Hex("@by_" + inner), nil
}

func (a *MD5CustomMssAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, "")
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5CustomMssAlgo) NeedAddToPredb() bool { return false }

func (a *MD5CustomMssAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
