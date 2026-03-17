package sha

import (
	"decipher/internal/ident"
	"decipher/internal/myutils"
	"encoding/hex"

	"decipher/internal/algo/types"
)

type SHA1PassSaltHexAlgo struct{}

func (a *SHA1PassSaltHexAlgo) Name() string { return "sha1($pass.$salt)_hex" }

func (a *SHA1PassSaltHexAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA1PassSaltHexAlgo) NeedSalt() bool { return true }

func (a *SHA1PassSaltHexAlgo) Seal(plaintext, secret string) (string, error) {
	// 对salt进行hex解码，只取前4个字符
	saltToDecode := secret
	if len(saltToDecode) > 4 {
		saltToDecode = saltToDecode[:4]
	}
	decodedSalt, err := hex.DecodeString(saltToDecode)
	if err != nil {
		return "", err
	}
	return sha1Hex(plaintext + string(decodedSalt)), nil
}

func (a *SHA1PassSaltHexAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA1PassSaltHexAlgo) NeedAddToPredb() bool { return false }

func (a *SHA1PassSaltHexAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 40)
}
