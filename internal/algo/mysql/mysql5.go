package mysql

import (
	"crypto/sha1"
	"decipher/internal/algo/types"
	"encoding/hex"
)

type MySQL5Algo struct{}

func (a *MySQL5Algo) Name() string { return "mysql5" }

func (a *MySQL5Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MySQL5Algo) Seal(plaintext, secret string) (string, error) {
	h := sha1.New()
	h.Write([]byte(plaintext))
	sum1 := h.Sum(nil)

	// 对于空字符串，MySQL5只进行一次SHA1哈希
	if plaintext == "" {
		return hex.EncodeToString(sum1), nil
	}

	h2 := sha1.New()
	h2.Write(sum1)
	return hex.EncodeToString(h2.Sum(nil)), nil
}

func (a *MySQL5Algo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, "")
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MySQL5Algo) NeedsPrecomputation() bool { return true }
