package sha

import (
	"github.com/winezer0/decipher/internal/ident"
	"github.com/winezer0/decipher/internal/myutils"
	"encoding/hex"

	"github.com/winezer0/decipher/internal/algo/types"
)

type SHA512SaltPassHexAlgo struct{}

func (a *SHA512SaltPassHexAlgo) Name() string { return "sha512($salt.$pass)_hex" }

func (a *SHA512SaltPassHexAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA512SaltPassHexAlgo) NeedSalt() bool { return true }

func (a *SHA512SaltPassHexAlgo) Seal(plaintext, secret string) (string, error) {
	// 对salt进行hex解码，只取前4个字符
	saltToDecode := secret
	if len(saltToDecode) > 4 {
		saltToDecode = saltToDecode[:4]
	}
	decodedSalt, err := hex.DecodeString(saltToDecode)
	if err != nil {
		return "", err
	}
	return sha512Hex(string(decodedSalt) + plaintext), nil
}

func (a *SHA512SaltPassHexAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA512SaltPassHexAlgo) NeedAddToPredb() bool { return false }

func (a *SHA512SaltPassHexAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 128)
}
