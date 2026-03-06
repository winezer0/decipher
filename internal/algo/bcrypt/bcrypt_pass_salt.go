package bcrypt

import (
	"decipher/internal/ident"

	"golang.org/x/crypto/bcrypt"

	"decipher/internal/algo/types"
)

type BcryptPassSaltAlgo struct{}

func (a *BcryptPassSaltAlgo) Name() string { return "bcrypt_pass_salt" }

func (a *BcryptPassSaltAlgo) GetAlgoType() types.AlgoType {
	return types.AlgoIsDynamic
}

func (a *BcryptPassSaltAlgo) NeedSalt() bool { return true }

func (a *BcryptPassSaltAlgo) NeedAddToPredb() bool {
	return false
}

// Seal 生成 bcrypt($pass.$salt) 哈希
// plaintext: 明文密码
// secret: 盐值
// 返回: 哈希值, nil
func (a *BcryptPassSaltAlgo) Seal(plaintext, secret string) (string, error) {
	// 组合 pass + salt
	combined := plaintext + secret
	hash, err := bcrypt.GenerateFromPassword([]byte(combined), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// Recover 验证 bcrypt($pass.$salt) 哈希
// token: 存储的 bcrypt 哈希值
// secret: 盐值
// candidatePlain: 待验证的明文
// 返回: 如果匹配返回 candidatePlain, nil；否则返回 "", ErrVerificationFailed
func (a *BcryptPassSaltAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	// 组合 pass + salt
	combined := candidatePlain + secret
	err := bcrypt.CompareHashAndPassword([]byte(token), []byte(combined))
	if err == nil {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *BcryptPassSaltAlgo) Identify(token string) bool {
	return ident.IsValidBcryptStr(token)
}
