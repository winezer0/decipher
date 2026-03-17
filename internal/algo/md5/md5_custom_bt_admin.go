package md5

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
	"decipher/internal/myutils"
)

type MD5BTAdminAlgo struct{}

func (a *MD5BTAdminAlgo) Name() string { return "md5_md5_md5_bt_admin" }

func (a *MD5BTAdminAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5BTAdminAlgo) NeedSalt() bool { return true }

func (a *MD5BTAdminAlgo) Seal(plaintext, secret string) (string, error) {
	inner := md5Hex(md5Hex(plaintext) + "_bt.cn")
	return md5Hex(inner + secret), nil
}

func (a *MD5BTAdminAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5BTAdminAlgo) NeedAddToPredb() bool { return false }
func (a *MD5BTAdminAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
