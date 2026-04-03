package sha

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
	"decipher/internal/myutils"
)

type SHA1PassSalt2Algo struct{}

func (a *SHA1PassSalt2Algo) Name() string { return "sha1($pass-$salt)" }

func (a *SHA1PassSalt2Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA1PassSalt2Algo) NeedSalt() bool { return true }

func (a *SHA1PassSalt2Algo) Seal(plaintext, secret string) (string, error) {
	return sha1Hex(plaintext + "-" + secret), nil
}

func (a *SHA1PassSalt2Algo) Recover(token, secret, candidatePlain string) (string, error) {
	computed := sha1Hex(candidatePlain + "-" + secret)
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA1PassSalt2Algo) NeedAddToPredb() bool { return false }

func (a *SHA1PassSalt2Algo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 40)
}
