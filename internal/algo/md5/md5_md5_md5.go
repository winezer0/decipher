package md5

import (
	"decipher/internal/algo/types"
)

type MD5TripleAlgo struct{}

func (a *MD5TripleAlgo) Name() string { return "md5(md5(md5($pass)))" }

func (a *MD5TripleAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5TripleAlgo) Seal(plaintext, secret string) (string, error) {
	return md5Hex(md5Hex(md5Hex(plaintext))), nil
}

func (a *MD5TripleAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, "")
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5TripleAlgo) NeedAddToPredb() bool { return true }
