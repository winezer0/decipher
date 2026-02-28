package argon2

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"decipher/internal/algo/types"

	"golang.org/x/crypto/argon2"
)

// TODO 该算法可能实际实现存在错误 因为可配置选项很多
// 123456 salt=66666666 UTF8
// $argon2i$v=19$m=4096,t=3,p=1$NjY2NjY2NjY$3CSqfFMEXam8HIRjv3LcEjwNrW5gP/cvGZJLvMYlKFo
// https://gchq.github.io/CyberChef/#recipe=Argon2 在线生成 得到的结果无法解密成功
type Argon2Algo struct{}

func (a *Argon2Algo) Name() string { return "argon2" }

func (a *Argon2Algo) GetAlgoType() types.AlgoType { return types.AlgoIsDynamic }

func (a *Argon2Algo) Seal(plaintext, secret string) (string, error) {
	saltBytes := []byte(secret)
	if len(saltBytes) == 0 {
		saltBytes = []byte("defaultsalt")
	}
	hash := argon2.IDKey([]byte(plaintext), saltBytes, 3, 64*1024, 4, 32)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s",
		base64.RawStdEncoding.EncodeToString(saltBytes),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

func (a *Argon2Algo) Recover(token, secret, candidatePlain string) (string, error) {
	params, salt, expectedHash, err := parseArgon2Hash(token)
	if err != nil {
		return "", types.ErrVerificationFailed
	}

	var computedHash []byte
	switch params.variant {
	case "argon2id":
		computedHash = argon2.IDKey([]byte(candidatePlain), salt, params.time, params.memory, params.threads, params.keyLen)
	case "argon2i":
		computedHash = argon2.Key([]byte(candidatePlain), salt, params.time, params.memory, params.threads, params.keyLen)
	case "argon2d":
		computedHash = argon2.Key([]byte(candidatePlain), salt, params.time, params.memory, params.threads, params.keyLen)
	default:
		return "", types.ErrVerificationFailed
	}

	if string(computedHash) == string(expectedHash) {
		return candidatePlain, nil
	}
	return "", types.ErrVerificationFailed
}

func (a *Argon2Algo) NeedsPrecomputation() bool { return false }

type argon2Params struct {
	variant string
	version int
	memory  uint32
	time    uint32
	threads uint8
	keyLen  uint32
	saltLen uint32
}

func parseArgon2Hash(hash string) (*argon2Params, []byte, []byte, error) {
	parts := strings.Split(hash, "$")
	if len(parts) < 6 {
		return nil, nil, nil, fmt.Errorf("invalid argon2 hash format")
	}

	params := &argon2Params{}
	params.variant = parts[1]

	for i := 2; i < len(parts); i++ {
		if strings.HasPrefix(parts[i], "v=") {
			version, err := strconv.Atoi(parts[i][2:])
			if err != nil {
				return nil, nil, nil, err
			}
			params.version = version
		} else if strings.HasPrefix(parts[i], "m=") {
			paramParts := strings.Split(parts[i], ",")
			for _, p := range paramParts {
				kv := strings.SplitN(p, "=", 2)
				if len(kv) != 2 {
					continue
				}
				switch kv[0] {
				case "m":
					memory, err := strconv.ParseUint(kv[1], 10, 32)
					if err != nil {
						return nil, nil, nil, err
					}
					params.memory = uint32(memory)
				case "t":
					time, err := strconv.ParseUint(kv[1], 10, 32)
					if err != nil {
						return nil, nil, nil, err
					}
					params.time = uint32(time)
				case "p":
					threads, err := strconv.ParseUint(kv[1], 10, 8)
					if err != nil {
						return nil, nil, nil, err
					}
					params.threads = uint8(threads)
				}
			}
		}
	}

	saltIndex := len(parts) - 2
	hashIndex := len(parts) - 1

	salt, err := base64.RawStdEncoding.DecodeString(parts[saltIndex])
	if err != nil {
		return nil, nil, nil, err
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[hashIndex])
	if err != nil {
		return nil, nil, nil, err
	}

	params.keyLen = uint32(len(expectedHash))
	params.saltLen = uint32(len(salt))

	return params, salt, expectedHash, nil
}
