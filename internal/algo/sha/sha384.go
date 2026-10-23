package sha

import (
	"crypto/sha512"
	"github.com/winezer0/decipher/internal/algo/types"
	"github.com/winezer0/decipher/internal/ident"
	"github.com/winezer0/decipher/internal/myutils"
	"encoding/hex"
	"io"
)

type SHA384Algo struct{}

func (a *SHA384Algo) Name() string { return "sha384($pass)" }

func (a *SHA384Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA384Algo) NeedSalt() bool { return false }

func (a *SHA384Algo) Seal(plaintext, secret string) (string, error) {
	h := sha512.New384()
	io.WriteString(h, plaintext)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (a *SHA384Algo) Recover(token, secret, candidatePlain string) (string, error) {
	h := sha512.New384()
	io.WriteString(h, candidatePlain)
	computed := hex.EncodeToString(h.Sum(nil))
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA384Algo) NeedAddToPredb() bool { return true }

func (a *SHA384Algo) Identify(token string) bool {
	//原始输出：SHA-384 算法的二进制输出长度为 48 字节（384 位 = 48×8 位）；
	//十六进制字符串长度：1 字节二进制对应 2 位十六进制字符，因此 SHA-384 哈希的十六进制形式固定为 48×2 = 96位；
	return ident.IsHashStringWithLen(token, 96)
}
