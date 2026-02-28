package md5

import (
	"decipher/internal/algo/types"
)

// MD5CustomGmshopAlgo sikula gmshop
type MD5CustomGmshopAlgo struct{}

func (a *MD5CustomGmshopAlgo) Name() string { return "md5_custom_gmshop" }

func (a *MD5CustomGmshopAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MD5CustomGmshopAlgo) Seal(plaintext, secret string) (string, error) {
	return md5Hex(md5Hex(plaintext) + "gmshop_salt_2020"), nil
}

func (a *MD5CustomGmshopAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	computed, _ := a.Seal(candidatePlain, "")
	if computed == token {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *MD5CustomGmshopAlgo) NeedsPrecomputation() bool { return true }
