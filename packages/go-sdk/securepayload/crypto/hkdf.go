package spcrypto

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

func DeriveSubkey(master []byte, purpose, version string, enabled bool) []byte {
	if !enabled {
		out := make([]byte, len(master))
		copy(out, master)
		return out
	}
	info := []byte(purpose + "|v" + version)
	out := make([]byte, 32)
	r := hkdf.New(sha256.New, master, nil, info)
	_, _ = io.ReadFull(r, out)
	return out
}
