package ntlm

import (
	"github.com/winezer0/decipher/internal/algo/types"
	"github.com/winezer0/decipher/internal/ident"
	"github.com/winezer0/decipher/internal/myutils"
	"encoding/hex"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

type NTLMAlgo struct{}

func (a *NTLMAlgo) Name() string { return "ntlm" }

func (a *NTLMAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *NTLMAlgo) NeedSalt() bool { return false }

func (a *NTLMAlgo) Seal(plaintext, secret string) (string, error) {
	u16 := utf16.Encode([]rune(plaintext))
	b := make([]byte, len(u16)*2)
	for i, v := range u16 {
		b[i*2] = byte(v)
		b[i*2+1] = byte(v >> 8)
	}

	h := md4.New()
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (a *NTLMAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, "")
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *NTLMAlgo) NeedAddToPredb() bool { return false }

func (a *NTLMAlgo) Identify(token string) bool {
	//原始哈希是 16 字节二进制数据（基于 MD4 算法对 Unicode 编码的密码计算得出）；
	//转为十六进制字符串后，长度固定为 16×2=32位（1 字节 = 2 位十六进制）；
	return ident.IsHashStringWithLen(token, 32)
}
