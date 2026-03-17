package md5

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
	"decipher/internal/myutils"
)

type MD5MD5SaltMD5PassAlgo struct{}

func (a *MD5MD5SaltMD5PassAlgo) Name() string { return "md5(md5($salt).md5($pass))" }

func (a *MD5MD5SaltMD5PassAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5MD5SaltMD5PassAlgo) NeedSalt() bool { return true }

func (a *MD5MD5SaltMD5PassAlgo) Seal(plaintext, secret string) (string, error) {
	return md5Hex(md5Hex(secret) + md5Hex(plaintext)), nil
}

func (a *MD5MD5SaltMD5PassAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5MD5SaltMD5PassAlgo) NeedAddToPredb() bool { return false }

func (a *MD5MD5SaltMD5PassAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
