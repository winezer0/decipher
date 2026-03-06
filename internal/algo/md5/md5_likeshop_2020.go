package md5

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
)

type MD5LikeShop2020Algo struct{}

func (a *MD5LikeShop2020Algo) Name() string { return "md5($pass.md5(y.$salt.x).2020)" }

func (a *MD5LikeShop2020Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5LikeShop2020Algo) NeedSalt() bool { return true }

func (a *MD5LikeShop2020Algo) Seal(plaintext, secret string) (string, error) {
	saltHash := md5Hex("y" + secret + "x")
	saltHash += "2020"
	return md5Hex(plaintext + saltHash), nil
}

func (a *MD5LikeShop2020Algo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5LikeShop2020Algo) NeedAddToPredb() bool { return true }
func (a *MD5LikeShop2020Algo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
