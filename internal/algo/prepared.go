package algo

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	hashmd5 "github.com/winezer0/decipher/internal/algo/md5"
	hashsha "github.com/winezer0/decipher/internal/algo/sha"
	"github.com/winezer0/decipher/internal/algo/types"
	"encoding/hex"
)

// PreparedDigest 仅保存目标摘要，准备后可由多个 Worker 只读共享。
type PreparedDigest struct {
	sum  [sha256.Size]byte
	size uint8
}

// DecodeDigest 每个逻辑目标准备一次；无效输入保留为不可匹配状态。
func DecodeDigest(token string) PreparedDigest {
	var target PreparedDigest
	size := hex.DecodedLen(len(token))
	if len(token)%2 != 0 || (size != 16 && size != 20 && size != 32) {
		return target
	}
	if _, err := hex.Decode(target.sum[:size], []byte(token)); err != nil {
		return PreparedDigest{}
	}
	target.size = uint8(size)
	return target
}

// Valid 表示目标具有受支持的长度且已通过完整十六进制校验。
func (target PreparedDigest) Valid() bool { return target.size != 0 }

// PreparedRecover 不携带候选或可变计算状态。
type PreparedRecover func(target *PreparedDigest, secret, candidatePlain string) (string, error)

// PreparePlainDigest only recognizes concrete, salt-independent implementations.
// The returned function computes a single candidate for immediate comparison;
// it retains no candidate values or runtime cache.
func PreparePlainDigest(a Algorithm) func(string) PreparedDigest {
	switch a.(type) {
	case *hashmd5.MD5Algo:
		return plainMD5Digest
	case *hashsha.SHA1Algo:
		return plainSHA1Digest
	case *hashsha.SHA256Algo:
		return plainSHA256Digest
	}
	return nil
}

func plainMD5Digest(plain string) PreparedDigest {
	sum := md5.Sum([]byte(plain))
	target := PreparedDigest{size: md5.Size}
	copy(target.sum[:], sum[:])
	return target
}

func plainSHA1Digest(plain string) PreparedDigest {
	sum := sha1.Sum([]byte(plain))
	target := PreparedDigest{size: sha1.Size}
	copy(target.sum[:], sum[:])
	return target
}

func plainSHA256Digest(plain string) PreparedDigest {
	return PreparedDigest{sum: sha256.Sum256([]byte(plain)), size: sha256.Size}
}

// PrepareRecover 返回验证函数及其十六进制目标长度，只匹配具体实现。
// 包装及嵌入类型返回 nil、0，继续调用自身 Identify 和 Recover。
func PrepareRecover(a Algorithm) (PreparedRecover, int) {
	switch a.(type) {
	case *hashmd5.MD5Algo:
		return recoverPreparedMD5, 32
	case *hashmd5.MD5SaltPassAlgo:
		return recoverPreparedMD5SaltPass, 32
	case *hashmd5.MD5PassSaltAlgo:
		return recoverPreparedMD5PassSalt, 32
	case *hashsha.SHA1Algo:
		return recoverPreparedSHA1, 40
	case *hashsha.SHA1SaltPassAlgo:
		return recoverPreparedSHA1SaltPass, 40
	case *hashsha.SHA1PassSaltAlgo:
		return recoverPreparedSHA1PassSalt, 40
	case *hashsha.SHA256Algo:
		return recoverPreparedSHA256, 64
	case *hashsha.SHA256SaltPassAlgo:
		return recoverPreparedSHA256SaltPass, 64
	case *hashsha.SHA256PassSaltAlgo:
		return recoverPreparedSHA256PassSalt, 64
	}
	return nil, 0
}

func recoverPreparedSHA256(target *PreparedDigest, secret, plain string) (string, error) {
	if target.size == sha256.Size && sha256.Sum256([]byte(plain)) == target.sum {
		return plain, nil
	}
	return "", types.ErrVerificationFailed
}

func recoverPreparedMD5(target *PreparedDigest, secret, plain string) (string, error) {
	if target.size == md5.Size && md5.Sum([]byte(plain)) == [md5.Size]byte(target.sum[:md5.Size]) {
		return plain, nil
	}
	return "", types.ErrVerificationFailed
}

func recoverPreparedMD5SaltPass(target *PreparedDigest, secret, plain string) (string, error) {
	if target.size != md5.Size {
		return "", types.ErrVerificationFailed
	}
	var sum [md5.Size]byte
	if preparedStackInput(secret, plain) {
		var buf [preparedInputBufferSize]byte
		sum = md5.Sum(joinPreparedInput(buf[:], secret, plain))
	} else {
		sum = md5.Sum([]byte(secret + plain))
	}
	if sum == [md5.Size]byte(target.sum[:md5.Size]) {
		return plain, nil
	}
	return "", types.ErrVerificationFailed
}

func recoverPreparedMD5PassSalt(target *PreparedDigest, secret, plain string) (string, error) {
	if target.size != md5.Size {
		return "", types.ErrVerificationFailed
	}
	var sum [md5.Size]byte
	if preparedStackInput(plain, secret) {
		var buf [preparedInputBufferSize]byte
		sum = md5.Sum(joinPreparedInput(buf[:], plain, secret))
	} else {
		sum = md5.Sum([]byte(plain + secret))
	}
	if sum == [md5.Size]byte(target.sum[:md5.Size]) {
		return plain, nil
	}
	return "", types.ErrVerificationFailed
}

func recoverPreparedSHA1(target *PreparedDigest, secret, plain string) (string, error) {
	if target.size == sha1.Size && sha1.Sum([]byte(plain)) == [sha1.Size]byte(target.sum[:sha1.Size]) {
		return plain, nil
	}
	return "", types.ErrVerificationFailed
}

func recoverPreparedSHA1SaltPass(target *PreparedDigest, secret, plain string) (string, error) {
	if target.size != sha1.Size {
		return "", types.ErrVerificationFailed
	}
	var sum [sha1.Size]byte
	if preparedStackInput(secret, plain) {
		var buf [preparedInputBufferSize]byte
		sum = sha1.Sum(joinPreparedInput(buf[:], secret, plain))
	} else {
		sum = sha1.Sum([]byte(secret + plain))
	}
	if sum == [sha1.Size]byte(target.sum[:sha1.Size]) {
		return plain, nil
	}
	return "", types.ErrVerificationFailed
}

func recoverPreparedSHA1PassSalt(target *PreparedDigest, secret, plain string) (string, error) {
	if target.size != sha1.Size {
		return "", types.ErrVerificationFailed
	}
	var sum [sha1.Size]byte
	if preparedStackInput(plain, secret) {
		var buf [preparedInputBufferSize]byte
		sum = sha1.Sum(joinPreparedInput(buf[:], plain, secret))
	} else {
		sum = sha1.Sum([]byte(plain + secret))
	}
	if sum == [sha1.Size]byte(target.sum[:sha1.Size]) {
		return plain, nil
	}
	return "", types.ErrVerificationFailed
}

func recoverPreparedSHA256SaltPass(target *PreparedDigest, secret, plain string) (string, error) {
	if target.size != sha256.Size {
		return "", types.ErrVerificationFailed
	}
	var sum [sha256.Size]byte
	if preparedStackInput(secret, plain) {
		var buf [preparedInputBufferSize]byte
		sum = sha256.Sum256(joinPreparedInput(buf[:], secret, plain))
	} else {
		sum = sha256.Sum256([]byte(secret + plain))
	}
	if sum == target.sum {
		return plain, nil
	}
	return "", types.ErrVerificationFailed
}

func recoverPreparedSHA256PassSalt(target *PreparedDigest, secret, plain string) (string, error) {
	if target.size != sha256.Size {
		return "", types.ErrVerificationFailed
	}
	var sum [sha256.Size]byte
	if preparedStackInput(plain, secret) {
		var buf [preparedInputBufferSize]byte
		sum = sha256.Sum256(joinPreparedInput(buf[:], plain, secret))
	} else {
		sum = sha256.Sum256([]byte(plain + secret))
	}
	if sum == target.sum {
		return plain, nil
	}
	return "", types.ErrVerificationFailed
}
