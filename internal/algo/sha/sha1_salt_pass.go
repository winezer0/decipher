package sha

import (
	"crypto/sha1"
	"github.com/winezer0/decipher/internal/algo/types"
	"github.com/winezer0/decipher/internal/ident"
)

type SHA1SaltPassAlgo struct{}

func (a *SHA1SaltPassAlgo) Name() string { return "sha1($salt.$pass)" }

func (a *SHA1SaltPassAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA1SaltPassAlgo) NeedSalt() bool { return true }

func (a *SHA1SaltPassAlgo) Seal(plaintext, secret string) (string, error) {
	return sha1Hex(secret + plaintext), nil
}

func (a *SHA1SaltPassAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	if sha1Matches(token, sha1.Sum([]byte(secret+candidatePlain))) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA1SaltPassAlgo) NeedAddToPredb() bool { return false }

func (a *SHA1SaltPassAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 40)
}
