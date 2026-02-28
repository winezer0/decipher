package sha

import (
	"crypto/sha512"
	"decipher/internal/algo/types"
	"encoding/hex"
	"io"
)

type SHA384Algo struct{}

func (a *SHA384Algo) Name() string { return "sha384" }

func (a *SHA384Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA384Algo) Seal(plaintext, secret string) (string, error) {
	h := sha512.New384()
	io.WriteString(h, plaintext)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (a *SHA384Algo) Recover(token, secret, candidatePlain string) (string, error) {
	h := sha512.New384()
	io.WriteString(h, candidatePlain)
	computed := hex.EncodeToString(h.Sum(nil))
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA384Algo) NeedsPrecomputation() bool { return true }
