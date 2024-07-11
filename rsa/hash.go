package rsa

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

func getHash(hashAlg string) (hash hash.Hash, err error) {
	switch hashAlg {
	case "SHA1":
		hash = sha1.New()
	case "SHA256":
		hash = sha256.New()
	case "SHA512":
		hash = sha512.New()
	default:
		err = fmt.Errorf("unexpected hashing algorithm")
	}
	return
}
