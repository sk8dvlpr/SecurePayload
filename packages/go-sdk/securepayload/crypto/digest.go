package spcrypto

import (
	"crypto/sha256"
	"encoding/base64"
)

func BodyDigestB64(body string) string {
	sum := sha256.Sum256([]byte(body))
	return base64.StdEncoding.EncodeToString(sum[:])
}
