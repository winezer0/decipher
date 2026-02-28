package md5

import (
	"decipher/internal/algo/types"
)

type MD5MiddleAlgo struct{}

func (a *MD5MiddleAlgo) Name() string { return "md5_middle" }

func (a *MD5MiddleAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

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

func (a *MD5MiddleAlgo) NeedsPrecomputation() bool { return true }
