package des

import (
	"crypto/des"
	"decipher/internal/algo/types"
	"decipher/internal/ident"
	"encoding/base64"
)

type CrmebAdminAlgo struct{}

func (a *CrmebAdminAlgo) Name() string { return "des_crmeb_admin" }

func (a *CrmebAdminAlgo) GetAlgoType() types.AlgoType { return types.AlgoIsEncrypt }

func (a *CrmebAdminAlgo) NeedSalt() bool { return true }

func (a *CrmebAdminAlgo) Seal(plaintext, secret string) (string, error) {
	if secret == "" {
		return "", types.ErrInvalidInput
	}

	key := a.prepareKey(secret)

	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}

	plaintextBytes := []byte(plaintext)
	blockSize := block.BlockSize()
	padding := blockSize - len(plaintextBytes)%blockSize
	padtext := make([]byte, len(plaintextBytes)+padding)
	copy(padtext, plaintextBytes)
	for i := len(plaintextBytes); i < len(padtext); i++ {
		padtext[i] = byte(padding)
	}

	encrypted := make([]byte, len(padtext))
	for i := 0; i < len(padtext); i += blockSize {
		block.Encrypt(encrypted[i:i+blockSize], padtext[i:i+blockSize])
	}

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (a *CrmebAdminAlgo) Recover(token, secret, candidatePlain string) (string, error) {
	if secret == "" {
		return "", types.ErrDecryptionFailed
	}

	key := a.prepareKey(secret)

	block, err := des.NewCipher(key)
	if err != nil {
		return "", types.ErrDecryptionFailed
	}

	encrypted, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", types.ErrDecryptionFailed
	}

	blockSize := block.BlockSize()
	if len(encrypted)%blockSize != 0 {
		return "", types.ErrDecryptionFailed
	}

	decrypted := make([]byte, len(encrypted))
	for i := 0; i < len(encrypted); i += blockSize {
		block.Decrypt(decrypted[i:i+blockSize], encrypted[i:i+blockSize])
	}

	if len(decrypted) == 0 {
		return "", types.ErrDecryptionFailed
	}
	padding := int(decrypted[len(decrypted)-1])
	if padding > blockSize || padding == 0 {
		return "", types.ErrDecryptionFailed
	}
	for i := len(decrypted) - padding; i < len(decrypted); i++ {
		if decrypted[i] != byte(padding) {
			return "", types.ErrDecryptionFailed
		}
	}

	result := decrypted[:len(decrypted)-padding]
	if !types.IsPrintableUTF8(result) {
		return "", types.ErrDecryptionFailed
	}

	return string(result), nil
}

func (a *CrmebAdminAlgo) NeedAddToPredb() bool { return false }

func (a *CrmebAdminAlgo) prepareKey(secret string) []byte {
	keyBytes := []byte(secret)
	if len(keyBytes) > 8 {
		keyBytes = keyBytes[:8]
	}
	if len(keyBytes) < 8 {
		padded := make([]byte, 8)
		copy(padded, keyBytes)
		for i := len(keyBytes); i < 8; i++ {
			padded[i] = 0x01
		}
		keyBytes = padded
	}
	return keyBytes
}

func Decrypt(encryptedBase64, secret string) (string, error) {
	algo := &CrmebAdminAlgo{}
	return algo.Recover(encryptedBase64, secret, "")
}

func (a *CrmebAdminAlgo) Identify(token string) bool {
	return ident.IsValidBase64Str(token)
}
