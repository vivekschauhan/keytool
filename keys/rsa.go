package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

func CreateKeyPair() (*rsa.PrivateKey, error) {
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, 4096)
	if err != nil {
		return nil, err
	}

	pub := key.PublicKey
	pubKeyASN1Bytes, err := x509.MarshalPKIXPublicKey(&pub)
	if err != nil {
		return nil, err
	}
	priKeyASN1Bytes := x509.MarshalPKCS1PrivateKey(key)

	os.WriteFile("public_key.pem", getPEMEncodedKey("PUBLIC KEY", pubKeyASN1Bytes), 0666)
	os.WriteFile("private_key.pem", getPEMEncodedKey("RSA PRIVATE KEY", priKeyASN1Bytes), 0666)

	return key, nil
}

func getPEMEncodedKey(keyType string, key []byte) []byte {
	publicKeyBlock := &pem.Block{
		Type:  keyType,
		Bytes: key,
	}
	return pem.EncodeToMemory(publicKeyBlock)
}

func ParsePublicKey(pub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse private key: " + err.Error())
	}

	return pk.(*rsa.PublicKey), nil
}

func ParsePrivateKey(private []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(private)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse private key: " + err.Error())
	}

	return pk, nil
}
