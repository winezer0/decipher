package md5

import (
	"github.com/winezer0/decipher/internal/algo/types"
	"github.com/winezer0/decipher/internal/ident"
	"github.com/winezer0/decipher/internal/myutils"
)

type MD5CustomByPwdAlgo struct{}

func (a *MD5CustomByPwdAlgo) Name() string { return "md5_custom_by_pwd" }

func (a *MD5CustomByPwdAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5CustomByPwdAlgo) NeedSalt() bool { return false }

func (a *MD5CustomByPwdAlgo) Seal(plaintext, secret string) (string, error) {
	inner := md5Hex(md5Hex(plaintext) + "pwd@2019")
	return md5Hex("@by_" + inner), nil
}

func (a *MD5CustomByPwdAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, "")
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5CustomByPwdAlgo) NeedAddToPredb() bool { return false }

func (a *MD5CustomByPwdAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
