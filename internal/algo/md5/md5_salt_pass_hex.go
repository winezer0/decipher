package md5

import (
	"github.com/winezer0/decipher/internal/ident"
	"github.com/winezer0/decipher/internal/myutils"
	"encoding/hex"

	"github.com/winezer0/decipher/internal/algo/types"
)

type MD5SaltPassHexAlgo struct{}

func (a *MD5SaltPassHexAlgo) Name() string { return "md5($salt.$pass)_hex" }

func (a *MD5SaltPassHexAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5SaltPassHexAlgo) NeedSalt() bool { return true }

func (a *MD5SaltPassHexAlgo) Seal(plaintext, secret string) (string, error) {
	// 对salt进行hex解码，只取前4个字符
	saltToDecode := secret
	if len(saltToDecode) > 4 {
		saltToDecode = saltToDecode[:4]
	}
	decodedSalt, err := hex.DecodeString(saltToDecode)
	if err != nil {
		return "", err
	}
	return md5Hex(string(decodedSalt) + plaintext), nil
}

func (a *MD5SaltPassHexAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5SaltPassHexAlgo) NeedAddToPredb() bool { return false }

func (a *MD5SaltPassHexAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
