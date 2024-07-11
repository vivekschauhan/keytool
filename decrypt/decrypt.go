package decrypt

import (
	"crypto/rsa"
	"encoding/base64"
	"strings"

	"github.com/vivekschauhan/keytool/aes"
	"github.com/vivekschauhan/keytool/jwe"
	krsa "github.com/vivekschauhan/keytool/rsa"
)

func Decrypt(key *rsa.PrivateKey, alg, hashAlg, msg string, useSymmetric, UseJwe bool) (string, error) {
	switch {
	case useSymmetric:
		return decryptWithSymmetricKey(key, alg, hashAlg, msg)
	case UseJwe:
		return decryptWithJWE(key, alg, hashAlg, msg)
	default:
		return decryptWithKey(key, alg, hashAlg, []byte(msg))
	}
}

func decryptWithKey(key *rsa.PrivateKey, alg, hashAlg string, encData []byte) (string, error) {
	data, err := krsa.Decrypt(key, alg, hashAlg, encData)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func decryptWithSymmetricKey(key *rsa.PrivateKey, alg, hashAlg, msg string) (string, error) {
	elements := strings.Split(msg, ".")
	encSymKey, _ := base64.URLEncoding.DecodeString(elements[0])
	encData, _ := base64.URLEncoding.DecodeString(elements[1])

	symmetricKey, err := decryptWithKey(key, alg, hashAlg, encSymKey)
	if err != nil {
		return "", err
	}
	data, err := aes.Decrypt([]byte(symmetricKey), encData)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func decryptWithJWE(key *rsa.PrivateKey, alg, hashAlg, msg string) (string, error) {
	decrypted, err := jwe.Decrypt(key, alg, hashAlg, msg)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}
