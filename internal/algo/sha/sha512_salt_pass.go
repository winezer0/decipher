package sha

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
)

type SHA512SaltPassAlgo struct{}

func (a *SHA512SaltPassAlgo) Name() string { return "sha512($salt.$pass)" }

func (a *SHA512SaltPassAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA512SaltPassAlgo) NeedSalt() bool { return true }

func (a *SHA512SaltPassAlgo) Seal(plaintext, secret string) (string, error) {
	return sha512Hex(secret + plaintext), nil
}

func (a *SHA512SaltPassAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed := sha512Hex(secret + candidatePlain)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA512SaltPassAlgo) NeedAddToPredb() bool { return true }

func (a *SHA512SaltPassAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 128)
}
