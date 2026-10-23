package md5

import (
	"crypto/md5"
	"github.com/winezer0/decipher/internal/ident"
	"encoding/hex"

	"github.com/winezer0/decipher/internal/algo/types"
)

// MD5Algo standard md5($pass)
type MD5Algo struct{}

func (a *MD5Algo) Name() string { return "md5($pass)" }

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
	return md5Hex(plaintext), nil
}

// Recover 验证 MD5 哈希
// token: 存储的哈希值
// secret: 盐值（可选）
// candidatePlain: 待验证的明文
// 返回: 如果匹配返回 candidatePlain, nil；否则返回 "", ErrVerificationFailed
func (a *MD5Algo) Recover(token, secret, candidatePlain string) (string, error) {
	if md5Matches(token, md5.Sum([]byte(candidatePlain))) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// md5Matches 直接比较摘要，避免每次验证构造十六进制字符串及小写副本。
func md5Matches(token string, sum [md5.Size]byte) bool {
	if len(token) != hex.EncodedLen(md5.Size) {
		return false
	}
	var expected [md5.Size]byte
	if _, err := hex.Decode(expected[:], []byte(token)); err != nil {
		return false
	}
	return expected == sum
}

func (a *MD5Algo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
