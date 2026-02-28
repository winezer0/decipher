package md5

import (
	"encoding/hex"

	"decipher/internal/algo/types"
)

type MD5MD5SaltMD5PassHexAlgo struct{}

func (a *MD5MD5SaltMD5PassHexAlgo) Name() string { return "md5(md5($salt).md5($pass))_hex" }

func (a *MD5MD5SaltMD5PassHexAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5MD5SaltMD5PassHexAlgo) Seal(plaintext, secret string) (string, error) {
	// 对salt进行hex解码，只取前4个字符
	saltToDecode := secret
	if len(saltToDecode) > 4 {
		saltToDecode = saltToDecode[:4]
	}
	decodedSalt, err := hex.DecodeString(saltToDecode)
	if err != nil {
		return "", err
	}
	return md5Hex(md5Hex(string(decodedSalt)) + md5Hex(plaintext)), nil
}

func (a *MD5MD5SaltMD5PassHexAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5MD5SaltMD5PassHexAlgo) NeedsPrecomputation() bool { return true }
