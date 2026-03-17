package md5

import (
	"decipher/internal/ident"
	"decipher/internal/myutils"
	"encoding/hex"

	"decipher/internal/algo/types"
)

type MD5PassSaltHexAlgo struct{}

func (a *MD5PassSaltHexAlgo) Name() string { return "md5($pass.$salt)_hex" }

func (a *MD5PassSaltHexAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5PassSaltHexAlgo) NeedSalt() bool { return true }

func (a *MD5PassSaltHexAlgo) Seal(plaintext, secret string) (string, error) {
	// 对salt进行hex解码，只取前4个字符
	saltToDecode := secret
	if len(saltToDecode) > 4 {
		saltToDecode = saltToDecode[:4]
	}
	decodedSalt, err := hex.DecodeString(saltToDecode)
	if err != nil {
		return "", err
	}
	return md5Hex(plaintext + string(decodedSalt)), nil
}

func (a *MD5PassSaltHexAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5PassSaltHexAlgo) NeedAddToPredb() bool { return false }

func (a *MD5PassSaltHexAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
