package sha

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
	"decipher/internal/myutils"
)

type SHA512PassSaltAlgo struct{}

func (a *SHA512PassSaltAlgo) Name() string { return "sha512($pass.$salt)" }

func (a *SHA512PassSaltAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA512PassSaltAlgo) NeedSalt() bool { return true }

func (a *SHA512PassSaltAlgo) Seal(plaintext, secret string) (string, error) {
	return sha512Hex(plaintext + secret), nil
}

func (a *SHA512PassSaltAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed := sha512Hex(candidatePlain + secret)
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}
func (a *SHA512PassSaltAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 128)
}

func (a *SHA512PassSaltAlgo) NeedAddToPredb() bool { return false }
