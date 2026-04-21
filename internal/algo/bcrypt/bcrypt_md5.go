package bcrypt

import (
	"crypto/md5"
	"decipher/internal/algo/types"
	"decipher/internal/ident"

	"golang.org/x/crypto/bcrypt"
)

type BcryptMd5Algo struct{}

func (a *BcryptMd5Algo) Name() string { return "bcrypt(md5($pass))" }

func (a *BcryptMd5Algo) GetAlgoType() types.AlgoType { return types.AlgoIsDynamic }

func (a *BcryptMd5Algo) NeedSalt() bool { return false }

func (a *BcryptMd5Algo) Seal(plaintext, secret string) (string, error) {
	md5Hash := md5Sum(plaintext)
	hash, err := bcrypt.GenerateFromPassword([]byte(md5Hash), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (a *BcryptMd5Algo) Recover(token, secret, candidatePlain string) (string, error) {
	md5Hash := md5Sum(candidatePlain)
	err := bcrypt.CompareHashAndPassword([]byte(token), []byte(md5Hash))
	if err == nil {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *BcryptMd5Algo) NeedAddToPredb() bool { return false }

func (a *BcryptMd5Algo) Identify(token string) bool {
	return ident.IsValidBcryptStr(token)
}

func md5Sum(plaintext string) string {
	h := md5.New()
	h.Write([]byte(plaintext))
	return string(h.Sum(nil))
}
