package sha

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
)

type SHA1Algo struct{}

func (a *SHA1Algo) Name() string { return "sha1" }

func (a *SHA1Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA1Algo) NeedSalt() bool { return false }

func (a *SHA1Algo) Seal(plaintext, secret string) (string, error) {
	return sha1Hex(plaintext), nil
}

func (a *SHA1Algo) Recover(token, secret, candidatePlain string) (string, error) {
	computed := sha1Hex(candidatePlain)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA1Algo) NeedAddToPredb() bool { return true }

func (a *SHA1Algo) Identify(token string) bool {
	//SHA-1（安全哈希算法 1）是经典的哈希算法，其核心格式特征：
	//原始哈希输出为 20 字节二进制数据（SHA-1 算法的固定输出长度）；
	//转为十六进制字符串后，长度固定为 20×2=40位（1 字节对应 2 位十六进制字符）；
	return ident.IsHashStringWithLen(token, 40)
}
