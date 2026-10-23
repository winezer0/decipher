package md5

import (
	"crypto/md5"
	"github.com/winezer0/decipher/internal/algo/types"
	"github.com/winezer0/decipher/internal/myutils"
	"encoding/base64"
	"io"
)

type MD5Base64Algo struct{}

func (a *MD5Base64Algo) Name() string { return "base64(md5($pass))" }

func (a *MD5Base64Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5Base64Algo) NeedSalt() bool { return false }

func (a *MD5Base64Algo) Seal(plaintext, secret string) (string, error) {
	m := md5.New()
	io.WriteString(m, plaintext)
	sum := m.Sum(nil)
	return base64.StdEncoding.EncodeToString(sum), nil
}

func (a *MD5Base64Algo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, "")
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5Base64Algo) NeedAddToPredb() bool { return false }

func (a *MD5Base64Algo) Identify(token string) bool {
	// 1. 尝试 Base64 解码
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return false
	}

	// 2. 检查解码后的长度是否为 16 (MD5 Hash Size)
	return len(decoded) == 16 || len(decoded) == 32
}
