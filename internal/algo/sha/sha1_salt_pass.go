package sha

import (
	"decipher/internal/algo/types"
)

type SHA1SaltPassAlgo struct{}

func (a *SHA1SaltPassAlgo) Name() string { return "sha1($salt.$pass)" }

func (a *SHA1SaltPassAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA1SaltPassAlgo) Seal(plaintext, secret string) (string, error) {
	return sha1Hex(secret + plaintext), nil
}

func (a *SHA1SaltPassAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed := sha1Hex(secret + candidatePlain)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA1SaltPassAlgo) NeedsPrecomputation() bool { return true }
