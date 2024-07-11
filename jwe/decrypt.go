package jwe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"encoding/base64"
	"strings"

	"github.com/pkg/errors"
	krsa "github.com/vivekschauhan/keytool/rsa"
)

type jweMsg struct {
	header       []byte
	encryptedCek []byte
	iv           []byte
	cipherText   []byte
	tags         []byte
}

func Decrypt(key *rsa.PrivateKey, keyAlg, hashAlg, msg string) ([]byte, error) {
	parseJwe, err := parseJweMsg(msg)
	if err != nil {
		return nil, err
	}

	cek, err := krsa.Decrypt(key, keyAlg, hashAlg, parseJwe.encryptedCek)
	if err != nil {
		return nil, err
	}

	encoder, err := gcmEncoder(cek)
	if err != nil {
		return nil, err
	}

	combined := make([]byte, len(parseJwe.cipherText)+len(parseJwe.tags))
	copy(combined, parseJwe.cipherText)
	copy(combined[len(parseJwe.cipherText):], parseJwe.tags)

	buf, err := encoder.Open(nil, parseJwe.iv, combined, parseJwe.header)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func parseJweElement(elements []string, index int, b64Decode bool) ([]byte, error) {
	if index < len(elements) {
		val := []byte(elements[index])
		if b64Decode {
			return base64.RawURLEncoding.DecodeString(string(val))
		}
		return val, nil
	}
	return nil, errors.New("invalid JWE element")
}

func parseJweMsg(msg string) (*jweMsg, error) {
	var err error
	jweMsg := &jweMsg{}

	elements := strings.Split(msg, ".")
	jweMsg.header, err = parseJweElement(elements, 0, false)
	if err != nil {
		return nil, err
	}

	jweMsg.encryptedCek, err = parseJweElement(elements, 1, true)
	if err != nil {
		return nil, err
	}

	jweMsg.iv, err = parseJweElement(elements, 2, true)
	if err != nil {
		return nil, err
	}

	jweMsg.cipherText, err = parseJweElement(elements, 3, true)
	if err != nil {
		return nil, err
	}

	jweMsg.tags, err = parseJweElement(elements, 4, true)
	if err != nil {
		return nil, err
	}

	return jweMsg, nil
}

func gcmEncoder(key []byte) (cipher.AEAD, error) {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}
	return aead, nil
}
