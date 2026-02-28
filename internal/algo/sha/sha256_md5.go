package sha

import (
	"crypto/md5"
	"decipher/internal/algo/types"
	"encoding/hex"
	"io"
)

type SHA256MD5Algo struct{}

func (a *SHA256MD5Algo) Name() string { return "sha256(md5($pass))" }

func (a *SHA256MD5Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA256MD5Algo) Seal(plaintext, secret string) (string, error) {
	m := md5.New()
	io.WriteString(m, plaintext)
	md5Str := hex.EncodeToString(m.Sum(nil))
	return sha256Hex(md5Str), nil
}

func (a *SHA256MD5Algo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, "")
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA256MD5Algo) NeedsPrecomputation() bool { return true }
