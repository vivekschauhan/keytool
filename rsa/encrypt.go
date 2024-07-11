package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func Encrypt(pk *rsa.PublicKey, alg, hashAlg string, data []byte) ([]byte, error) {
	hash, err := getHash(hashAlg)
	if err != nil {
		return nil, err
	}

	switch alg {
	case "RSA-OAEP":
		bts, err := rsa.EncryptOAEP(hash, rand.Reader, pk, data, nil)
		return bts, err
	case "PKCS":
		bts, err := rsa.EncryptPKCS1v15(rand.Reader, pk, data)
		return bts, err
	default:
		return nil, fmt.Errorf("unexpected algorithm")
	}
}
