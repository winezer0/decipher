package md5

import (
	"decipher/internal/algo/types"
	"golang.org/x/text/encoding/unicode"
)

type MD5UnicodeAlgo struct{}

func (a *MD5UnicodeAlgo) Name() string { return "md5(unicode($pass))" }

func (a *MD5UnicodeAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5UnicodeAlgo) Seal(plaintext, secret string) (string, error) {
	enc := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	unicodeBytes, _ := enc.Bytes([]byte(plaintext))
	return md5Hex(string(unicodeBytes)), nil
}

func (a *MD5UnicodeAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, "")
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5UnicodeAlgo) NeedsPrecomputation() bool { return true }
