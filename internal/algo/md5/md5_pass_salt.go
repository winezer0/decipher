package md5

import (
	"crypto/md5"
	"github.com/winezer0/decipher/internal/algo/types"
	"github.com/winezer0/decipher/internal/ident"
)

type MD5PassSaltAlgo struct{}

func (a *MD5PassSaltAlgo) Name() string { return "md5($pass.$salt)" }

func (a *MD5PassSaltAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5PassSaltAlgo) NeedSalt() bool { return true }

func (a *MD5PassSaltAlgo) Seal(plaintext, secret string) (string, error) {
	return md5Hex(plaintext + secret), nil
}

func (a *MD5PassSaltAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	if md5Matches(token, md5.Sum([]byte(candidatePlain+secret))) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5PassSaltAlgo) NeedAddToPredb() bool { return false }

func (a *MD5PassSaltAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
