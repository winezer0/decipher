package md5

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
)

// MD5CustomLizhiAlgo md5(username;password)
type MD5CustomLizhiAlgo struct{}

func (a *MD5CustomLizhiAlgo) Name() string { return "md5_custom_lizhi" }

func (a *MD5CustomLizhiAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5CustomLizhiAlgo) NeedSalt() bool { return true }

func (a *MD5CustomLizhiAlgo) Seal(plaintext, secret string) (string, error) {
	return md5Hex(secret + ";" + plaintext), nil
}

func (a *MD5CustomLizhiAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5CustomLizhiAlgo) NeedAddToPredb() bool { return false }

func (a *MD5CustomLizhiAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
