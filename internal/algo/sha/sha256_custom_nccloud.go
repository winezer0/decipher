package sha

import (
	"crypto/sha256"
	"decipher/internal/algo/types"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

type SHA256CustomNcCloudAlgo struct{}

func (a *SHA256CustomNcCloudAlgo) Name() string { return "sha256_custom_nccloud" }

func (a *SHA256CustomNcCloudAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *SHA256CustomNcCloudAlgo) NeedSalt() bool { return true }

func (a *SHA256CustomNcCloudAlgo) Seal(plaintext, secret string) (string, error) {
	combined := secret + plaintext

	h := sha256.New()
	h.Write([]byte(combined))
	sha256Hash := hex.EncodeToString(h.Sum(nil))

	hashBytes, _ := hex.DecodeString(sha256Hash)
	base64Encoded := base64.StdEncoding.EncodeToString(hashBytes)

	return "S_S++" + base64Encoded, nil
}

func (a *SHA256CustomNcCloudAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, secret)
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *SHA256CustomNcCloudAlgo) NeedAddToPredb() bool { return false }

func (a *SHA256CustomNcCloudAlgo) Identify(token string) bool {
	return strings.HasPrefix(token, "S_S++")
}
