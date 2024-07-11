package jwe

import (
	"crypto/rsa"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/pkg/errors"
)

func Encrypt(key *rsa.PublicKey, alg, hashAlg, keyAlg string, data []byte) ([]byte, error) {
	keyEncAlg, err := getKeyAlg(alg, hashAlg)
	if err != nil {
		return nil, err
	}
	contentEncAlg, err := getContentAlg(keyAlg, hashAlg)
	if err != nil {
		return nil, err
	}
	encrypted, err := jwe.Encrypt(data, keyEncAlg, key, contentEncAlg, jwa.NoCompress)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func getKeyAlg(alg, hashAlg string) (jwa.KeyEncryptionAlgorithm, error) {
	switch alg {
	case "RSA-OAEP":
		if hashAlg == "SHA256" {
			return jwa.RSA_OAEP_256, nil
		}
		return jwa.RSA_OAEP, nil
	default:
		return "", errors.Errorf(`unsupported key encryption algorithm (%s)`, alg)
	}
}

func getContentAlg(alg, hashAlg string) (jwa.ContentEncryptionAlgorithm, error) {
	switch alg {
	case "AES-GCM":
		switch hashAlg {
		case "SHA256":
			return jwa.A256GCM, nil
		default:
			return "", errors.Errorf(`unsupported content encryption algorithm (%s)`, alg)
		}
	default:
		return "", errors.Errorf(`unsupported content encryption algorithm (%s)`, alg)
	}
}
