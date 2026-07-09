package spcrypto

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

func SignHMAC(msg string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(msg))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func SignEd25519Detached(message, seed64 []byte) ([]byte, error) {
	if len(seed64) != ed25519.PrivateKeySize {
		return nil, errors.New("ukuran kunci Ed25519 tidak valid")
	}
	return ed25519.Sign(ed25519.PrivateKey(seed64), message), nil
}

func VerifyEd25519Detached(message, sig, pub []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), message, sig)
}
