package md5

import (
	"crypto/md5"
	"decipher/internal/algo/types"
	"encoding/base64"
	"io"
)

type MD5Base64Algo struct{}

func (a *MD5Base64Algo) Name() string { return "base64(md5($pass))" }

func (a *MD5Base64Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5Base64Algo) Seal(plaintext, secret string) (string, error) {
	m := md5.New()
	io.WriteString(m, plaintext)
	sum := m.Sum(nil)
	return base64.StdEncoding.EncodeToString(sum), nil
}

func (a *MD5Base64Algo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, "")
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5Base64Algo) NeedAddToPredb() bool { return true }
