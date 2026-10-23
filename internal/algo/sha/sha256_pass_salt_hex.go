package sha

import (
	"github.com/winezer0/decipher/internal/ident"
	"github.com/winezer0/decipher/internal/myutils"
	"encoding/hex"

	"github.com/winezer0/decipher/internal/algo/types"
)

type SHA256PassSaltHexAlgo struct{}

func (a *SHA256PassSaltHexAlgo) Name() string { return "sha256($pass.$salt)_hex" }

func (a *SHA256PassSaltHexAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA256PassSaltHexAlgo) NeedSalt() bool { return true }

func (a *SHA256PassSaltHexAlgo) Seal(plaintext, secret string) (string, error) {
	// 对salt进行hex解码，只取前4个字符
	saltToDecode := secret
	if len(saltToDecode) > 4 {
		saltToDecode = saltToDecode[:4]
	}
	decodedSalt, err := hex.DecodeString(saltToDecode)
	if err != nil {
		return "", err
	}
	return sha256Hex(plaintext + string(decodedSalt)), nil
}

func (a *SHA256PassSaltHexAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if myutils.EqualString(computed, token, true) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}
func (a *SHA256PassSaltHexAlgo) NeedAddToPredb() bool { return false }

func (a *SHA256PassSaltHexAlgo) Identify(token string) bool {
	return ident.IsHashStringWithLen(token, 64)
}
