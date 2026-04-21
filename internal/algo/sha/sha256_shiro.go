package sha

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
	"decipher/internal/myutils"
)

type SHA256ShiroAlgo struct{}

func (a *SHA256ShiroAlgo) Name() string { return "sha256($pass.$salt);shiro" }

func (a *SHA256ShiroAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA256ShiroAlgo) NeedSalt() bool { return true }

func (a *SHA256ShiroAlgo) Seal(plaintext, secret string) (string, error) {
	return sha256Hex(plaintext + secret), nil
}

func (a *SHA256ShiroAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA256ShiroAlgo) NeedAddToPredb() bool { return false }

func (a *SHA256ShiroAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 64)
}
