package md5

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
)

type MD5MiddleAlgo struct{}

func (a *MD5MiddleAlgo) Name() string { return "md5_middle" }

func (a *MD5MiddleAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5MiddleAlgo) NeedSalt() bool { return false }

func (a *MD5MiddleAlgo) Seal(plaintext, secret string) (string, error) {
	h := md5Hex(plaintext)
	if len(h) == 32 {
		return h[8:24], nil
	}
	return "", types.ErrInvalidInput
}

func (a *MD5MiddleAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, "")
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5MiddleAlgo) NeedAddToPredb() bool { return true }

func (a *MD5MiddleAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 16)
}
