package scrypt

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"decipher/internal/algo/types"

	"golang.org/x/crypto/scrypt"
)

type ScryptAlgo struct{}

func (a *ScryptAlgo) Name() string { return "scrypt" }

func (a *ScryptAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsDynamic }

func (a *ScryptAlgo) Seal(plaintext, secret string) (string, error) {
	saltBytes := []byte(secret)
	if len(saltBytes) == 0 {
		saltBytes = []byte("defaultsalt")
	}
	hash, err := scrypt.Key([]byte(plaintext), saltBytes, 16384, 8, 1, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("$scrypt$N=16384,r=8,p=1$%s$%s",
		base64.StdEncoding.EncodeToString(saltBytes),
		base64.StdEncoding.EncodeToString(hash)), nil
}

func (a *ScryptAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	params, salt, expectedHash, err := parseScryptHash(token)
	if err != nil {
		return "", types.ErrVerificationFailed
	}

	computedHash, err := scrypt.Key([]byte(candidatePlain), salt, params.N, params.r, params.p, params.keyLen)
	if err != nil {
		return "", types.ErrVerificationFailed
	}

	if string(computedHash) == string(expectedHash) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *ScryptAlgo) NeedAddToPredb() bool { return false }

type scryptParams struct {
	N      int
	r      int
	p      int
	keyLen int
}

func parseScryptHash(hash string) (*scryptParams, []byte, []byte, error) {
	parts := strings.Split(hash, "$")
	if len(parts) < 5 {
		return nil, nil, nil, fmt.Errorf("invalid scrypt hash format")
	}

	params := &scryptParams{
		N:      16384,
		r:      8,
		p:      1,
		keyLen: 32,
	}

	for i := 2; i < len(parts); i++ {
		if strings.Contains(parts[i], "N=") || strings.Contains(parts[i], "r=") || strings.Contains(parts[i], "p=") {
			paramParts := strings.Split(parts[i], ",")
			for _, p := range paramParts {
				kv := strings.SplitN(p, "=", 2)
				if len(kv) != 2 {
					continue
				}
				switch kv[0] {
				case "N":
					N, err := strconv.Atoi(kv[1])
					if err != nil {
						return nil, nil, nil, err
					}
					params.N = N
				case "r":
					r, err := strconv.Atoi(kv[1])
					if err != nil {
						return nil, nil, nil, err
					}
					params.r = r
				case "p":
					p, err := strconv.Atoi(kv[1])
					if err != nil {
						return nil, nil, nil, err
					}
					params.p = p
				}
			}
		}
	}

	saltIndex := len(parts) - 2
	hashIndex := len(parts) - 1

	salt, err := base64.StdEncoding.DecodeString(parts[saltIndex])
	if err != nil {
		salt, err = base64.RawStdEncoding.DecodeString(parts[saltIndex])
		if err != nil {
			return nil, nil, nil, err
		}
	}

	expectedHash, err := base64.StdEncoding.DecodeString(parts[hashIndex])
	if err != nil {
		expectedHash, err = base64.RawStdEncoding.DecodeString(parts[hashIndex])
		if err != nil {
			return nil, nil, nil, err
		}
	}

	params.keyLen = len(expectedHash)

	return params, salt, expectedHash, nil
}
