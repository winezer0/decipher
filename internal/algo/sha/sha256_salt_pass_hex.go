package sha

import (
	"encoding/hex"

	"decipher/internal/algo/types"
)

type SHA256SaltPassHexAlgo struct{}

func (a *SHA256SaltPassHexAlgo) Name() string { return "sha256($salt.$pass)_hex" }

func (a *SHA256SaltPassHexAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA256SaltPassHexAlgo) Seal(plaintext, secret string) (string, error) {
	// 对salt进行hex解码，只取前4个字符
	saltToDecode := secret
	if len(saltToDecode) > 4 {
		saltToDecode = saltToDecode[:4]
	}
	decodedSalt, err := hex.DecodeString(saltToDecode)
	if err != nil {
		return "", err
	}
	return sha256Hex(string(decodedSalt) + plaintext), nil
}

func (a *SHA256SaltPassHexAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA256SaltPassHexAlgo) NeedsPrecomputation() bool { return true }
