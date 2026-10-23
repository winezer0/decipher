package md5

import (
	"github.com/winezer0/decipher/internal/algo/types"
	"github.com/winezer0/decipher/internal/ident"
	"github.com/winezer0/decipher/internal/myutils"
)

type MD5TripleAlgo struct{}

func (a *MD5TripleAlgo) Name() string { return "md5(md5(md5($pass)))" }

func (a *MD5TripleAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5TripleAlgo) NeedSalt() bool { return false }

func (a *MD5TripleAlgo) Seal(plaintext, secret string) (string, error) {
	return md5Hex(md5Hex(md5Hex(plaintext))), nil
}

func (a *MD5TripleAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, "")
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5TripleAlgo) NeedAddToPredb() bool { return true }

func (a *MD5TripleAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
