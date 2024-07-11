package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func Decrypt(key *rsa.PrivateKey, alg, hashAlg string, data []byte) ([]byte, error) {
	hash, err := getHash(hashAlg)
	if err != nil {
		return nil, err
	}

	switch alg {
	case "RSA-OAEP":
		return rsa.DecryptOAEP(hash, rand.Reader, key, data, nil)
	case "PKCS":
		return rsa.DecryptPKCS1v15(rand.Reader, key, data)
	default:
		return nil, fmt.Errorf("unexpected algorithm")
	}
}
