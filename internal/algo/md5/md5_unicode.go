package md5

import (
	"github.com/winezer0/decipher/internal/algo/types"
	"github.com/winezer0/decipher/internal/ident"
	"github.com/winezer0/decipher/internal/myutils"

	"golang.org/x/text/encoding/unicode"
)

type MD5UnicodeAlgo struct{}

func (a *MD5UnicodeAlgo) Name() string { return "md5(unicode($pass))" }

func (a *MD5UnicodeAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5UnicodeAlgo) NeedSalt() bool { return false }

func (a *MD5UnicodeAlgo) Seal(plaintext, secret string) (string, error) {
	enc := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	unicodeBytes, _ := enc.Bytes([]byte(plaintext))
	return md5Hex(string(unicodeBytes)), nil
}

func (a *MD5UnicodeAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, "")
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5UnicodeAlgo) NeedAddToPredb() bool { return true }

func (a *MD5UnicodeAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
