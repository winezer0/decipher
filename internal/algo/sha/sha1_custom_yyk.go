package sha

import (
	"decipher/internal/algo/types"
	"decipher/internal/ident"
)

type SHA1CustomYYKAlgo struct{}

func (a *SHA1CustomYYKAlgo) Name() string { return "sha1_custom_yyk" }

func (a *SHA1CustomYYKAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA1CustomYYKAlgo) NeedSalt() bool { return true }

func (a *SHA1CustomYYKAlgo) Seal(plaintext, secret string) (string, error) {
	return sha1Hex(plaintext + "-" + secret), nil
}

func (a *SHA1CustomYYKAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed := sha1Hex(candidatePlain + "-" + secret)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA1CustomYYKAlgo) NeedAddToPredb() bool { return false }

func (a *SHA1CustomYYKAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 40)
}
