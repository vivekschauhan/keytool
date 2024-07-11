package aes

func Decrypt(symmetricKey, data []byte) ([]byte, error) {
	gcm, err := gcmEncoder(symmetricKey)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, err
	}

	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	decrypted, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}
