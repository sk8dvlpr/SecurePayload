package securepayload

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	spcrypto "github.com/sk8dvlpr/securepayload-go/securepayload/crypto"
)

// Verify memverifikasi request (server-side) tanpa panic.
func (c *Client) Verify(headers map[string]string, rawBody, method, path string, query interface{}) VerifyResult {
	data, err := c.VerifyOrThrow(headers, rawBody, method, path, query)
	if err != nil {
		if spErr, ok := err.(*Error); ok {
			return VerifyResult{
				OK: false, Status: spErr.Status, Error: spErr.Message,
				Debug: spErr.Context, Mode: "", BodyPlain: "", JSON: nil,
			}
		}
		return VerifyResult{OK: false, Status: StatusBadRequest, Error: err.Error(), JSON: nil}
	}
	return VerifyResult{OK: true, Mode: data.Mode, BodyPlain: data.BodyPlain, JSON: data.JSON}
}

// VerifyOrThrow memverifikasi request dan mengembalikan error jika gagal.
func (c *Client) VerifyOrThrow(headers map[string]string, rawBody, method, path string, query interface{}) (*VerifyData, error) {
	H := normalizeHeaders(headers)
	ver := H["X-SIGNATURE-VERSION"]
	cid := H["X-CLIENT-ID"]
	kid := H["X-KEY-ID"]
	tsStr := H["X-TIMESTAMP"]
	nonceB64 := H["X-NONCE"]

	if ver == "" || cid == "" || kid == "" || tsStr == "" || nonceB64 == "" {
		return nil, newError(StatusBadRequest, "Header keamanan tidak lengkap", nil)
	}
	if ver != c.opts.Version {
		return nil, newError(StatusBadRequest, "Versi protokol tidak didukung", nil)
	}
	if !digitsRe.MatchString(tsStr) {
		return nil, newError(StatusBadRequest, "Format timestamp salah", nil)
	}
	var ts int64
	_, _ = fmt.Sscanf(tsStr, "%d", &ts)
	now := c.opts.Clock()
	if ts > now+int64(c.opts.ClockSkew) || ts < now-int64(c.opts.ReplayTTL+c.opts.ClockSkew) {
		return nil, newError(StatusUnauthorized, "Timestamp di luar batas wajar (kadaluarsa atau jam salah)", nil)
	}
	if c.opts.ReplayStore != nil {
		sum := sha256ReplayKey(cid, kid, nonceB64)
		if !c.opts.ReplayStore(sum, c.opts.ReplayTTL+c.opts.ClockSkew) {
			return nil, newError(StatusUnauthorized, "Replay detected", nil)
		}
	}

	m := strings.ToUpper(method)
	p := spcrypto.NormalizePath(path)
	if p == "" {
		p = "/"
	}
	qStr := spcrypto.CanonicalQuery(parseQueryInput(query))
	keys := c.resolveKeys(cid, kid)
	bodyForSign := rawBody

	if c.opts.Mode == ModeAEAD || c.opts.Mode == ModeBoth {
		if H["X-AEAD-ALGORITHM"] != spcrypto.AEADAlg {
			return nil, newError(StatusUnauthorized, fmt.Sprintf("Mode %s mewajibkan enkripsi AEAD, namun header AEAD tidak ada atau algoritmanya tidak dikenal", c.opts.Mode), nil)
		}
		var parsed map[string]string
		if err := json.Unmarshal([]byte(rawBody), &parsed); err != nil {
			return nil, newError(StatusBadRequest, "Payload AEAD tidak ditemukan", nil)
		}
		blobB64 := parsed["__aead_b64"]
		if blobB64 == "" {
			return nil, newError(StatusBadRequest, "Payload AEAD tidak ditemukan", nil)
		}
		keyRaw := spcrypto.SafeB64Decode(keys.AEADKeyB64)
		if keyRaw == nil || len(keyRaw) != 32 {
			return nil, newError(StatusServerError, "Kunci AEAD server tidak valid/tersedia", nil)
		}
		key := spcrypto.DeriveSubkey(keyRaw, spcrypto.KDFPurposeAeadReq, c.opts.Version, c.opts.DeriveKeys)
		nonceCalc := spcrypto.AeadNonceFrom(nonceB64, m, p, qStr)
		nonceHdr := spcrypto.SafeB64Decode(H["X-AEAD-NONCE"])
		if nonceHdr == nil {
			nonceHdr = []byte{}
		}
		if subtle.ConstantTimeCompare(nonceHdr, nonceCalc) != 1 {
			return nil, newError(StatusUnauthorized, "Nonce mismatch (Integritas request invalid)", nil)
		}
		ct := spcrypto.SafeB64Decode(blobB64)
		if ct == nil {
			return nil, newError(StatusBadRequest, "Format base64 body rusak", nil)
		}
		aad := []byte(spcrypto.BuildRequestAeadAad(c.opts.Version, tsStr, collectBoundHeaders(headers, c.opts.BindHeaders)))
		plain, err := spcrypto.DecryptAEAD(key, nonceCalc, aad, ct)
		if err != nil {
			return nil, newError(StatusUnauthorized, "Gagal mendekripsi (Kunci salah atau data rusak)", nil)
		}
		bodyForSign = string(plain)
		if c.opts.Mode == ModeAEAD {
			var j interface{}
			_ = json.Unmarshal(plain, &j)
			return &VerifyData{Mode: "AEAD", BodyPlain: bodyForSign, JSON: j}, nil
		}
		calc := "sha256=" + spcrypto.BodyDigestB64(bodyForSign)
		if H["X-BODY-DIGEST"] != calc {
			return nil, newError(StatusUnprocessable, "Integritas Body Digest gagal", nil)
		}
	}

	if c.opts.Mode == ModeHMAC || c.opts.Mode == ModeBoth {
		expectedAlg := spcrypto.HMACAlg
		if c.opts.SignAlg == SignAlgEd25519 {
			expectedAlg = spcrypto.Ed25519Alg
		}
		alg := H["X-SIGNATURE-ALGORITHM"]
		sigIn := H["X-SIGNATURE"]
		dig := H["X-BODY-DIGEST"]
		if alg != expectedAlg || sigIn == "" || dig == "" {
			return nil, newError(StatusBadRequest, "Header tanda tangan tidak lengkap/salah algoritma", nil)
		}
		digVal := strings.TrimPrefix(dig, "sha256=")
		if digVal == dig {
			return nil, newError(StatusBadRequest, "Format digest salah (harus sha256=...)", nil)
		}
		calcDig := spcrypto.BodyDigestB64(bodyForSign)
		if subtle.ConstantTimeCompare([]byte(digVal), []byte(calcDig)) != 1 {
			return nil, newError(StatusUnprocessable, "Integritas Body Digest HMAC gagal", nil)
		}
		msg := spcrypto.HMACMessage(c.opts.Version, cid, kid, tsStr, nonceB64, m, p, qStr, calcDig)
		if c.opts.SignAlg == SignAlgEd25519 {
			pub := spcrypto.SafeB64Decode(keys.Ed25519PublicKeyB64)
			if pub == nil || len(pub) != 32 {
				return nil, newError(StatusServerError, "Public key Ed25519 server tidak valid/tersedia", nil)
			}
			sig := spcrypto.SafeB64Decode(sigIn)
			if sig == nil || len(sig) != 64 {
				return nil, newError(StatusBadRequest, "Format signature Ed25519 rusak", nil)
			}
			if !spcrypto.VerifyEd25519Detached([]byte(msg), sig, pub) {
				return nil, newError(StatusUnauthorized, "Tanda Tangan (Ed25519) tidak valid", nil)
			}
		} else {
			if len(keys.HMACSecret) < 32 {
				return nil, newError(StatusServerError, "Secret Key HMAC tidak ditemukan di server", nil)
			}
			signKey := spcrypto.DeriveSubkey([]byte(keys.HMACSecret), spcrypto.KDFPurposeSignReq, c.opts.Version, c.opts.DeriveKeys)
			if subtle.ConstantTimeCompare([]byte(spcrypto.SignHMAC(msg, signKey)), []byte(sigIn)) != 1 {
				return nil, newError(StatusUnauthorized, "Tanda Tangan (Signature) tidak valid", nil)
			}
		}
		mode := "HMAC"
		if c.opts.Mode == ModeBoth {
			mode = "BOTH"
		}
		var j interface{}
		_ = json.Unmarshal([]byte(bodyForSign), &j)
		return &VerifyData{Mode: mode, BodyPlain: bodyForSign, JSON: j}, nil
	}

	return nil, newError(StatusBadRequest, "Tidak ditemukan header keamanan yang valid", nil)
}

func sha256ReplayKey(clientID, keyID, nonceB64 string) string {
	sum := sha256.Sum256([]byte(clientID + "|" + keyID + "|" + nonceB64))
	return hex.EncodeToString(sum[:])
}
