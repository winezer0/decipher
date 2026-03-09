package md5

import (
	"decipher/internal/ident"
	"encoding/hex"

	"decipher/internal/algo/types"
)

type MD5PassMD5SaltHexAlgo struct{}

func (a *MD5PassMD5SaltHexAlgo) Name() string { return "md5($pass.md5($salt))_hex" }

func (a *MD5PassMD5SaltHexAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5PassMD5SaltHexAlgo) NeedSalt() bool { return true }

func (a *MD5PassMD5SaltHexAlgo) Seal(plaintext, secret string) (string, error) {
	// 对salt进行hex解码，只取前4个字符
	saltToDecode := secret
	if len(saltToDecode) > 4 {
		saltToDecode = saltToDecode[:4]
	}
	decodedSalt, err := hex.DecodeString(saltToDecode)
	if err != nil {
		return "", err
	}
	return md5Hex(plaintext + md5Hex(string(decodedSalt))), nil
}

func (a *MD5PassMD5SaltHexAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5PassMD5SaltHexAlgo) NeedAddToPredb() bool { return false }

func (a *MD5PassMD5SaltHexAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 32)
}
