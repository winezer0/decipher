package sha

import (
	"crypto/md5"
	"decipher/internal/algo/types"
	"decipher/internal/ident"
	"encoding/hex"
	"io"
)

type SHA256MD5Algo struct{}

func (a *SHA256MD5Algo) Name() string { return "sha256(md5($pass))" }

func (a *SHA256MD5Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA256MD5Algo) NeedSalt() bool { return false }

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

func (a *SHA256MD5Algo) NeedAddToPredb() bool { return true }

func (a *SHA256MD5Algo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 64)
}
