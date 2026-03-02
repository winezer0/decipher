package sha

import (
	"decipher/internal/algo/types"
)

type SHA1PassSaltAlgo struct{}

func (a *SHA1PassSaltAlgo) Name() string { return "sha1($pass.$salt)" }

func (a *SHA1PassSaltAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA1PassSaltAlgo) Seal(plaintext, secret string) (string, error) {
	return sha1Hex(plaintext + secret), nil
}

func (a *SHA1PassSaltAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed := sha1Hex(candidatePlain + secret)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA1PassSaltAlgo) NeedAddToPredb() bool { return true }
