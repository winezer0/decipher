package md5

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
	"decipher/internal/myutils"
)

// MD5PassSaltAlgo2 md5(username;password)
type MD5PassSaltAlgo2 struct{}

func (a *MD5PassSaltAlgo2) Name() string { return "md5($salt;$pass)" }

func (a *MD5PassSaltAlgo2) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5PassSaltAlgo2) NeedSalt() bool { return true }

func (a *MD5PassSaltAlgo2) Seal(plaintext, secret string) (string, error) {
	return md5Hex(secret + ";" + plaintext), nil
}

func (a *MD5PassSaltAlgo2) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5PassSaltAlgo2) NeedAddToPredb() bool { return false }

func (a *MD5PassSaltAlgo2) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
