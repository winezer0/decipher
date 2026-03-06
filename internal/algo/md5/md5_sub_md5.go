package md5

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
)

type MD5SubAlgo struct{}

func (a *MD5SubAlgo) Name() string { return "md5(substring(md5($pass),8,16))" }

func (a *MD5SubAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5SubAlgo) NeedSalt() bool { return false }

func (a *MD5SubAlgo) Seal(plaintext, secret string) (string, error) {
	m1 := md5Hex(plaintext)
	if len(m1) == 32 {
		sub := m1[8:24]
		return md5Hex(sub), nil
	}
	return "", types.ErrInvalidInput
}

func (a *MD5SubAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, "")
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5SubAlgo) NeedAddToPredb() bool { return true }

func (a *MD5SubAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
