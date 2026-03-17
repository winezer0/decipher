package sha

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
	"decipher/internal/myutils"
)

type SHA1PassSaltAlgo struct{}

func (a *SHA1PassSaltAlgo) Name() string { return "sha1($pass.$salt)" }

func (a *SHA1PassSaltAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA1PassSaltAlgo) NeedSalt() bool { return true }

func (a *SHA1PassSaltAlgo) Seal(plaintext, secret string) (string, error) {
	return sha1Hex(plaintext + secret), nil
}

func (a *SHA1PassSaltAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed := sha1Hex(candidatePlain + secret)
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA1PassSaltAlgo) NeedAddToPredb() bool { return false }

func (a *SHA1PassSaltAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 40)
}
