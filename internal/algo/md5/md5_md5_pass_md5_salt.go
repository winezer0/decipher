package md5

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
	"decipher/internal/myutils"
)

type MD5MD5PassMD5SaltAlgo struct{}

func (a *MD5MD5PassMD5SaltAlgo) Name() string { return "md5(md5($pass).md5($salt))" }

func (a *MD5MD5PassMD5SaltAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5MD5PassMD5SaltAlgo) NeedSalt() bool { return true }

func (a *MD5MD5PassMD5SaltAlgo) Seal(plaintext, secret string) (string, error) {
	return md5Hex(md5Hex(plaintext) + md5Hex(secret)), nil
}

func (a *MD5MD5PassMD5SaltAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5MD5PassMD5SaltAlgo) NeedAddToPredb() bool { return false }

func (a *MD5MD5PassMD5SaltAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
