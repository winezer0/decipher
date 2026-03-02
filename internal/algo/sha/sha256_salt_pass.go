package sha

import (
	"decipher/internal/algo/types"
)

type SHA256SaltPassAlgo struct{}

func (a *SHA256SaltPassAlgo) Name() string { return "sha256($salt.$pass)" }

func (a *SHA256SaltPassAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA256SaltPassAlgo) Seal(plaintext, secret string) (string, error) {
	return sha256Hex(secret + plaintext), nil
}

func (a *SHA256SaltPassAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed := sha256Hex(secret + candidatePlain)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA256SaltPassAlgo) NeedAddToPredb() bool { return true }
