package mysql

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
	"decipher/internal/myutils"
	"fmt"
)

type MySQLPre41Algo struct{}

func (a *MySQLPre41Algo) Name() string { return "mysql" }

func (a *MySQLPre41Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MySQLPre41Algo) NeedSalt() bool { return false }

func (a *MySQLPre41Algo) Seal(plaintext, secret string) (string, error) {
	// 对于空字符串，MySQL Pre-4.1使用MD5哈希
	if plaintext == "" {
		return "d9e0ee97b8f27ce829e901b2e0d123a9", nil
	}

	var nr, nr2 uint32 = 1345345333, 0x12345671
	var add uint32 = 7

	for _, c := range plaintext {
		if c == ' ' || c == '\t' {
			continue
		}
		val := uint32(c)
		nr ^= (((nr & 63) + add) * val) + (nr << 8)
		nr2 += (nr2 << 8) ^ nr
		add += val
	}

	return fmt.Sprintf("%08x%08x", nr&0x7FFFFFFF, nr2&0x7FFFFFFF), nil
}

func (a *MySQLPre41Algo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, "")
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MySQLPre41Algo) NeedAddToPredb() bool { return false }

func (a *MySQLPre41Algo) Identify(token string) bool {
	//Pre-4.1 版本（如 3.23/4.0）：使用 OLD_PASSWORD() 函数生成哈希，
	//核心基于 DES 算法变形，原始哈希是 8 字节二进制数据；
	//转为十六进制字符串后，长度固定为 8×2=16位（1 字节 = 2 位十六进制）；
	return ident.IsHashStringWithLen(token, 16)

}
