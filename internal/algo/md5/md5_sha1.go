package md5

import (
	"crypto/sha1"
	"decipher/internal/algo/types"
	"decipher/internal/ident"
	"decipher/internal/myutils"
	"encoding/hex"
	"io"
)

type MD5SHA1Algo struct{}

func (a *MD5SHA1Algo) Name() string { return "md5(sha1($pass))" }

func (a *MD5SHA1Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5SHA1Algo) NeedSalt() bool { return false }

func (a *MD5SHA1Algo) Seal(plaintext, secret string) (string, error) {
	s := sha1.New()
	io.WriteString(s, plaintext)
	sha1Str := hex.EncodeToString(s.Sum(nil))
	return md5Hex(sha1Str), nil
}

func (a *MD5SHA1Algo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, "")
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5SHA1Algo) NeedAddToPredb() bool { return true }

func (a *MD5SHA1Algo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
