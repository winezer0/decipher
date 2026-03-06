package base64

import (
	"decipher/internal/ident"
	"encoding/base64"

	"decipher/internal/algo/types"
)

type Base64Algo struct{}

func (a *Base64Algo) Name() string { return "base64" }

func (a *Base64Algo) GetAlgoType() types.AlgoType {
	return types.AlgoIsEncrypt
}

func (a *Base64Algo) NeedSalt() bool {
	return false
}

func (a *Base64Algo) NeedAddToPredb() bool {
	return false
}

func (a *Base64Algo) Seal(plaintext, secret string) (string, error) {
	return base64.StdEncoding.EncodeToString([]byte(plaintext)), nil
}

func (a *Base64Algo) Recover(token, secret, candidatePlain string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", types.ErrDecryptionFailed
	}

	if !types.IsPrintableUTF8(decoded) {
		return "", types.ErrDecryptionFailed
	}

	return string(decoded), nil
}

func (a *Base64Algo) Identify(token string) bool {
	return ident.IsValidBase64Str(token)
}
