package sha

import (
	"crypto/sha1"
	"decipher/internal/algo/types"
	"encoding/hex"
	"io"
)

type SHA1Algo struct{}

func (a *SHA1Algo) Name() string { return "sha1" }

func (a *SHA1Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA1Algo) Seal(plaintext, secret string) (string, error) {
	return sha1Hex(plaintext), nil
}

func (a *SHA1Algo) Recover(token, secret, candidatePlain string) (string, error) {
	computed := sha1Hex(candidatePlain)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA1Algo) NeedAddToPredb() bool { return true }

func sha1Hex(s string) string {
	h := sha1.New()
	io.WriteString(h, s)
	return hex.EncodeToString(h.Sum(nil))
}
