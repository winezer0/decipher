package sha

import (
	"crypto/sha512"
	"github.com/winezer0/decipher/internal/algo/types"
	"github.com/winezer0/decipher/internal/ident"
	"github.com/winezer0/decipher/internal/myutils"
	"encoding/hex"
	"io"
)

type SHA512Algo struct{}

func (a *SHA512Algo) Name() string { return "sha512($pass)" }

func (a *SHA512Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA512Algo) NeedSalt() bool { return false }

func (a *SHA512Algo) Seal(plaintext, secret string) (string, error) {
	h := sha512.New()
	io.WriteString(h, plaintext)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (a *SHA512Algo) Recover(token, secret, candidatePlain string) (string, error) {
	h := sha512.New()
	io.WriteString(h, candidatePlain)
	computed := hex.EncodeToString(h.Sum(nil))
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA512Algo) NeedAddToPredb() bool { return true }

func (a *SHA512Algo) Identify(token string) bool {
	//原始二进制输出：SHA-512 算法生成的哈希值为 64 字节（512 位 = 64×8 位）；
	//十六进制字符串长度：1 字节二进制对应 2 位十六进制字符，因此 SHA-512 哈希的十六进制形式固定为 64×2 = 128位；
	return ident.IsHashStringWithLen(token, 128)
}
