package phpass

import (
	"crypto/md5"
	"decipher/internal/algo/types"
	"strings"
)

type PHPassAlgo struct{}

func (a *PHPassAlgo) Name() string { return "phpass" }

func (a *PHPassAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsDynamic }

func (a *PHPassAlgo) Seal(plaintext, secret string) (string, error) {
	return "", nil
}

func (a *PHPassAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	if len(token) < 12 {
		return "", types.ErrVerificationFailed
	}

	if !strings.HasPrefix(token, "$P$") && !strings.HasPrefix(token, "$H$") {
		return "", types.ErrVerificationFailed
	}

	if verifyPHPass(token, candidatePlain) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *PHPassAlgo) NeedsPrecomputation() bool { return false }

func verifyPHPass(hash, plaintext string) bool {
	if len(hash) < 12 {
		return false
	}

	var itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

	countLog2 := strings.Index(itoa64, string(hash[3]))
	if countLog2 < 7 || countLog2 > 30 {
		return false
	}
	count := 1 << uint(countLog2)

	salt := hash[4:12]
	if len(salt) != 8 {
		return false
	}

	hasher := md5.New()
	hasher.Write([]byte(salt))
	hasher.Write([]byte(plaintext))
	computed := hasher.Sum(nil)

	for i := 0; i < count; i++ {
		hasher.Reset()
		hasher.Write(computed)
		hasher.Write([]byte(plaintext))
		computed = hasher.Sum(nil)
	}

	expected := hash[12:]
	computedHash := encode64(computed, len(computed), itoa64)

	return computedHash == expected
}

func encode64(input []byte, count int, itoa64 string) string {
	output := ""
	i := 0

	for i < count {
		value := uint(input[i])
		i++
		output += string(itoa64[value&0x3f])
		if i < count {
			value |= uint(input[i]) << 8
		}
		output += string(itoa64[(value>>6)&0x3f])
		if i >= count {
			break
		}
		i++
		if i < count {
			value |= uint(input[i]) << 16
		}
		output += string(itoa64[(value>>12)&0x3f])
		if i >= count {
			break
		}
		i++
		output += string(itoa64[(value>>18)&0x3f])
	}

	return output
}
