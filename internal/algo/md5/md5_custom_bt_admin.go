package md5

import (
	"decipher/internal/algo/types"
)

type MD5BTAdminAlgo struct{}

func (a *MD5BTAdminAlgo) Name() string { return "md5_md5_md5_bt_admin" }

func (a *MD5BTAdminAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5BTAdminAlgo) Seal(plaintext, secret string) (string, error) {
	inner := md5Hex(md5Hex(plaintext) + "_bt.cn")
	return md5Hex(inner + secret), nil
}

func (a *MD5BTAdminAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5BTAdminAlgo) NeedsPrecomputation() bool { return true }
