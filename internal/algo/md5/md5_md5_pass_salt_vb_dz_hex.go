package md5

import (
	"github.com/winezer0/decipher/internal/ident"
	"github.com/winezer0/decipher/internal/myutils"
	"encoding/hex"

	"github.com/winezer0/decipher/internal/algo/types"
)

type MD5MD5PassSaltVBDZHexAlgo struct{}

func (a *MD5MD5PassSaltVBDZHexAlgo) Name() string { return "md5(md5($pass).$salt);VB;DZ_hex" }

func (a *MD5MD5PassSaltVBDZHexAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5MD5PassSaltVBDZHexAlgo) NeedSalt() bool { return true }

func (a *MD5MD5PassSaltVBDZHexAlgo) Seal(plaintext, secret string) (string, error) {
	// 对salt进行hex解码，只取前4个字符
	saltToDecode := secret
	if len(saltToDecode) > 4 {
		saltToDecode = saltToDecode[:4]
	}
	decodedSalt, err := hex.DecodeString(saltToDecode)
	if err != nil {
		return "", err
	}
	return md5Hex(md5Hex(plaintext) + string(decodedSalt)), nil
}

func (a *MD5MD5PassSaltVBDZHexAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5MD5PassSaltVBDZHexAlgo) NeedAddToPredb() bool { return false }

func (a *MD5MD5PassSaltVBDZHexAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
