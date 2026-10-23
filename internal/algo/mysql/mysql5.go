package mysql

import (
	"crypto/sha1"
	"github.com/winezer0/decipher/internal/algo/types"
	"github.com/winezer0/decipher/internal/ident"
	"github.com/winezer0/decipher/internal/myutils"
	"encoding/hex"
)

type MySQL5Algo struct{}

func (a *MySQL5Algo) Name() string { return "mysql5" }

func (a *MySQL5Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MySQL5Algo) NeedSalt() bool { return false }

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
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MySQL5Algo) NeedAddToPredb() bool { return false }

func (a *MySQL5Algo) Identify(token string) bool {
	//MySQL 5.x（包括 5.0/5.1/5.5/5.6/5.7 等）默认使用 SHA1 算法存储密码哈希：
	//原始哈希是 20 字节二进制数据（SHA1 算法的标准输出）；
	//转为十六进制字符串后，长度固定为 20×2=40位（1 字节 = 2 位十六进制）；
	return ident.IsHashStringWithLen(token, 40)
}
