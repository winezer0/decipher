package md5

import (
	"crypto/md5"
	"decipher/internal/ident"
	"decipher/internal/myutils"
	"encoding/hex"
	"io"

	"decipher/internal/algo/types"
)

// MD5Algo standard md5($pass)
type MD5Algo struct{}

func (a *MD5Algo) Name() string { return "md5" }

func (a *MD5Algo) GetAlgoType() types.AlgoType {
	return types.AlgoIsStatic
}

func (a *MD5Algo) NeedSalt() bool { return false }

func (a *MD5Algo) NeedAddToPredb() bool {
	return true
}

// Seal 生成 MD5 哈希
// plaintext: 明文密码
// secret: 盐值（可选）
// 返回: 哈希值, nil
func (a *MD5Algo) Seal(plaintext, secret string) (string, error) {
	if secret != "" {
		return md5Hex(plaintext), nil
	}
	return md5Hex(plaintext), nil
}

// Recover 验证 MD5 哈希
// token: 存储的哈希值
// secret: 盐值（可选）
// candidatePlain: 待验证的明文
// 返回: 如果匹配返回 candidatePlain, nil；否则返回 "", ErrVerificationFailed
func (a *MD5Algo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, err := a.Seal(candidatePlain, secret)
	if err != nil {
		return "", err
	}
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func md5Hex(s string) string {
	h := md5.New()
	io.WriteString(h, s)
	return hex.EncodeToString(h.Sum(nil))
}

func (a *MD5Algo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
