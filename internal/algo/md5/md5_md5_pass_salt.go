package md5

import (
	"github.com/winezer0/decipher/internal/algo/types"
	"github.com/winezer0/decipher/internal/ident"
	"github.com/winezer0/decipher/internal/myutils"
)

// MD5MD5PassSaltAlgo wanlshop 等cms
type MD5MD5PassSaltAlgo struct{}

func (a *MD5MD5PassSaltAlgo) Name() string { return "md5(md5($pass).$salt)" }

func (a *MD5MD5PassSaltAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5MD5PassSaltAlgo) NeedSalt() bool { return true }

func (a *MD5MD5PassSaltAlgo) Seal(plaintext, secret string) (string, error) {
	return md5Hex(md5Hex(plaintext) + secret), nil
}

func (a *MD5MD5PassSaltAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5MD5PassSaltAlgo) NeedAddToPredb() bool { return false }

func (a *MD5MD5PassSaltAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
