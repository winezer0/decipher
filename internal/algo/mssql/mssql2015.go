package mssql

import (
	"crypto/sha1"
	"decipher/internal/algo/types"
	"decipher/internal/ident"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf16"
)

type MSSQL2015Algo struct{}

func (a *MSSQL2015Algo) Name() string { return "MSSQL2015" }

func (a *MSSQL2015Algo) GetAlgoType() types.AlgoType { return types.AlgoIsStatic }

func (a *MSSQL2015Algo) NeedSalt() bool { return true }

func parseMSSQLSalt(secret string) []byte {
	if len(secret) == 0 {
		return make([]byte, 4)
	}

	saltHex := secret
	if len(saltHex)%2 != 0 {
		saltHex = saltHex + "0"
	}
	if len(saltHex) < 8 {
		for len(saltHex) < 8 {
			saltHex = saltHex + "00"
		}
	}

	decoded, err := hex.DecodeString(saltHex[:8])
	if err != nil {
		saltBytes := make([]byte, 4)
		copy(saltBytes, []byte(secret))
		for i := len([]byte(secret)); i < 4; i++ {
			saltBytes[i] = 0x00
		}
		return saltBytes
	}

	return decoded
}

func (a *MSSQL2015Algo) Seal(plaintext, secret string) (string, error) {
	saltBytes := parseMSSQLSalt(secret)

	u16 := utf16.Encode([]rune(plaintext))
	passBytes := make([]byte, len(u16)*2)
	for i, v := range u16 {
		passBytes[i*2] = byte(v)
		passBytes[i*2+1] = byte(v >> 8)
	}

	h := sha1.New()
	h.Write(passBytes)
	h.Write(saltBytes)
	hash := h.Sum(nil)

	return fmt.Sprintf("0x0100%s%s", hex.EncodeToString(saltBytes), hex.EncodeToString(hash)), nil
}

func (a *MSSQL2015Algo) Recover(token, secret, candidatePlain string) (string, error) {
	// 从 token 中提取 salt
	// token 格式: 0x0100 + saltHex(8 chars) + hashHex(40 chars)
	// 示例: 0x0100666660002712815c5906d66b8def6bff96296f973c46cf2d
	// saltHex 位于索引 6 到 14
	if len(token) >= 14 {
		saltHex := token[6:14]
		computed, _ := a.Seal(candidatePlain, saltHex)
		if strings.EqualFold(computed, token) {
			return candidatePlain, nil
		}
	} else {
		// Fallback: 如果token格式无效，则使用所提供的密钥（尽管“识别”功能应该能够检测到这种情况）
		computed, _ := a.Seal(candidatePlain, secret)
		if strings.EqualFold(computed, token) {
			return candidatePlain, nil
		}
	}

	return "", types.ErrVerificationFailed
}

func (a *MSSQL2015Algo) NeedAddToPredb() bool { return false }

func (a *MSSQL2015Algo) Identify(token string) bool {
	// 1. 核心前缀校验
	if !strings.HasPrefix(token, "0x0100") {
		return false
	}

	// 2. 精准长度校验：固定54个字符（0x0100 + 8+40 = 6+48=54）
	// 注意：如果是 SHA512 版本 (0x0200)，长度会不同，但这里只处理 0x0100
	if len(token) != 54 {
		return false
	}

	// 3. 校验前缀后所有字符都是十六进制（0-9/a-f/A-F）
	return ident.IsHashHexString(token[6:])
}
