package bcrypt

import (
	"golang.org/x/crypto/bcrypt"

	"decipher/internal/algo/types"
)

type BcryptAlgo struct{}

func (a *BcryptAlgo) Name() string { return "bcrypt" }

func (a *BcryptAlgo) GetAlgoType() types.AlgoType {
	return types.AlgoIsDynamic
}

func (a *BcryptAlgo) NeedAddToPredb() bool {
	return false
}

// Seal 生成 bcrypt 哈希
// plaintext: 明文密码
// secret: 盐值（bcrypt 使用内置盐，此参数被忽略）
// 返回: 哈希值, nil
func (a *BcryptAlgo) Seal(plaintext, secret string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// Recover 验证 bcrypt 哈希
// token: 存储的 bcrypt 哈希值
// secret: 盐值（bcrypt 使用内置盐，此参数被忽略）
// candidatePlain: 待验证的明文
// 返回: 如果匹配返回 candidatePlain, nil；否则返回 "", ErrVerificationFailed
func (a *BcryptAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	err := bcrypt.CompareHashAndPassword([]byte(token), []byte(candidatePlain))
	if err == nil {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}
