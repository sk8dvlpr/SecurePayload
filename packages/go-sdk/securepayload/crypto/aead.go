package spcrypto

import (
	"golang.org/x/crypto/chacha20poly1305"
)

func EncryptAEAD(key, nonce, aad, plain []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plain, aad), nil
}

func DecryptAEAD(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}
