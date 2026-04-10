package md5

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
	"decipher/internal/myutils"
)

type MD5LikeShop2021Algo struct{}

func (a *MD5LikeShop2021Algo) Name() string { return "md5($pass.md5(y.$salt.x).2021)" }

func (a *MD5LikeShop2021Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5LikeShop2021Algo) NeedSalt() bool { return true }

func (a *MD5LikeShop2021Algo) Seal(plaintext, secret string) (string, error) {
	saltHash := md5Hex("y" + secret + "x")
	saltHash += "2021"
	return md5Hex(plaintext + saltHash), nil
}

func (a *MD5LikeShop2021Algo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5LikeShop2021Algo) NeedAddToPredb() bool { return false }

func (a *MD5LikeShop2021Algo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
