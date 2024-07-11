package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
)

func hashedKey(key []byte) []byte {
	hash := sha256.New()
	hash.Write(key)
	return hash.Sum(nil)
}

func gcmEncoder(key []byte) (cipher.AEAD, error) {
	h := hashedKey(key)
	block, err := aes.NewCipher(h)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm, nil
}
