package sha

import (
	"crypto/sha256"
	"decipher/internal/algo/types"
	"decipher/internal/ident"
)

type SHA256SaltPassAlgo struct{}

func (a *SHA256SaltPassAlgo) Name() string { return "sha256($salt.$pass)" }

func (a *SHA256SaltPassAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA256SaltPassAlgo) NeedSalt() bool { return true }

func (a *SHA256SaltPassAlgo) Seal(plaintext, secret string) (string, error) {
	return sha256Hex(secret + plaintext), nil
}

func (a *SHA256SaltPassAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	if sha256Matches(token, sha256.Sum256([]byte(secret+candidatePlain))) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA256SaltPassAlgo) NeedAddToPredb() bool { return false }

func (a *SHA256SaltPassAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 64)
}
