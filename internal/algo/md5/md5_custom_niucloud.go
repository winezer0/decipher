package md5

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
	"decipher/internal/myutils"
)

type MD5DoubleNiuCloudAlgo struct{}

func (a *MD5DoubleNiuCloudAlgo) Name() string { return "md5(md5($pass).NiuCloud)" }

func (a *MD5DoubleNiuCloudAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5DoubleNiuCloudAlgo) NeedSalt() bool { return false }

func (a *MD5DoubleNiuCloudAlgo) Seal(plaintext, secret string) (string, error) {
	return md5Hex(md5Hex(plaintext) + "NiuCloud"), nil
}

func (a *MD5DoubleNiuCloudAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, "")
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5DoubleNiuCloudAlgo) NeedAddToPredb() bool { return false }

func (a *MD5DoubleNiuCloudAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
