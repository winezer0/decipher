package sha

import (
	"decipher/internal/ident"
	"encoding/hex"

	"decipher/internal/algo/types"
)

type SHA1SaltPassHexAlgo struct{}

func (a *SHA1SaltPassHexAlgo) Name() string { return "sha1($salt.$pass)_hex" }

func (a *SHA1SaltPassHexAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA1SaltPassHexAlgo) NeedSalt() bool { return true }

func (a *SHA1SaltPassHexAlgo) Seal(plaintext, secret string) (string, error) {
	// 对salt进行hex解码，只取前4个字符
	saltToDecode := secret
	if len(saltToDecode) > 4 {
		saltToDecode = saltToDecode[:4]
	}
	decodedSalt, err := hex.DecodeString(saltToDecode)
	if err != nil {
		return "", err
	}
	return sha1Hex(string(decodedSalt) + plaintext), nil
}

func (a *SHA1SaltPassHexAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA1SaltPassHexAlgo) NeedAddToPredb() bool { return true }

func (a *SHA1SaltPassHexAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 40)
}
