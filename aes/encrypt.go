package aes

import (
	"crypto/rand"
	"io"
)

func Encrypt(symmetricKey, data []byte) ([]byte, error) {
	gcm, err := gcmEncoder(symmetricKey)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	encrypted := gcm.Seal(nonce, nonce, []byte(data), nil)
	s := string(encrypted)
	return []byte(s), nil
}
