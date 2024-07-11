package encrypt

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"
	"github.com/vivekschauhan/keytool/aes"
	"github.com/vivekschauhan/keytool/jwe"
	krsa "github.com/vivekschauhan/keytool/rsa"
)

func Encrypt(key *rsa.PublicKey, alg, hashAlg, data string, useSymmetric, UseJwe bool) (string, error) {
	switch {
	case useSymmetric:
		return encryptWithSymmetricKey(key, alg, hashAlg, []byte(data))
	case UseJwe:
		return encryptWithJWE(key, alg, hashAlg, []byte(data))
	default:
		return encryptWithKey(key, alg, hashAlg, []byte(data))
	}
}

func encryptWithKey(key *rsa.PublicKey, alg, hashAlg string, data []byte) (string, error) {
	encData, err := krsa.Encrypt(key, alg, hashAlg, data)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(encData), nil
}

func encryptWithSymmetricKey(key *rsa.PublicKey, alg, hashAlg string, data []byte) (string, error) {
	symmetricKey := uuid.New().String()
	fmt.Printf("generated symmetric key: %s\n", symmetricKey)

	encData, err := aes.Encrypt([]byte(symmetricKey), data)
	if err != nil {
		return "", err
	}

	encKey, err := encryptWithKey(key, alg, hashAlg, []byte(symmetricKey))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", encKey, base64.URLEncoding.EncodeToString(encData)), nil
}

func encryptWithJWE(key *rsa.PublicKey, alg, hashAlg string, data []byte) (string, error) {
	encrypted, err := jwe.Encrypt(key, alg, hashAlg, "AES-GCM", data)
	if err != nil {
		return "", err
	}
	return string(encrypted), nil
}
