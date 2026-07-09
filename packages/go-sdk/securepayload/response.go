package securepayload

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	spcrypto "github.com/sk8dvlpr/securepayload-go/securepayload/crypto"
)

// BuildResponse membangun response aman (server-side).
func (c *Client) BuildResponse(requestHeaders map[string]string, payload map[string]interface{}) (map[string]string, string, error) {
	H := normalizeHeaders(requestHeaders)
	reqNonceB64 := H["X-NONCE"]
	if reqNonceB64 == "" {
		return nil, "", newError(StatusBadRequest, "Nonce request tidak ditemukan untuk binding response", nil)
	}
	cid := H["X-CLIENT-ID"]
	kid := H["X-KEY-ID"]
	keys := c.resolveKeys(cid, kid)

	ver := c.opts.Version
	respTs := fmt.Sprintf("%d", c.opts.Clock())
	respNonceB64 := c.opts.RespNonceGen()

	headers := map[string]string{
		"X-Resp-Timestamp":         respTs,
		"X-Resp-Nonce":             respNonceB64,
		"X-Resp-Signature-Version": ver,
	}

	plain, err := jsonEncode(payload)
	if err != nil {
		return nil, "", newError(StatusBadRequest, "Gagal encode JSON response", nil)
	}
	bodyOut := plain

	if c.opts.Mode == ModeAEAD || c.opts.Mode == ModeBoth {
		raw := spcrypto.SafeB64Decode(keys.AEADKeyB64)
		if raw == nil || len(raw) != 32 {
			return nil, "", newError(StatusServerError, "Kunci AEAD response tidak valid/tersedia", nil)
		}
		key := spcrypto.DeriveSubkey(raw, spcrypto.KDFPurposeAeadResp, c.opts.Version, c.opts.DeriveKeys)
		nonce := spcrypto.RespAeadNonceFrom(respNonceB64, reqNonceB64)
		aad := []byte(spcrypto.BuildResponseAeadAad(ver, reqNonceB64, respTs))
		ct, err := spcrypto.EncryptAEAD(key, nonce, aad, []byte(plain))
		if err != nil {
			return nil, "", newError(StatusBadRequest, "Gagal enkripsi AEAD response", nil)
		}
		bodyOut, err = aeadBody(base64.StdEncoding.EncodeToString(ct))
		if err != nil {
			return nil, "", err
		}
		headers["X-Resp-AEAD-Algorithm"] = spcrypto.AEADAlg
		headers["X-Resp-AEAD-Nonce"] = base64.StdEncoding.EncodeToString(nonce)
	}

	if c.opts.Mode == ModeHMAC || c.opts.Mode == ModeBoth {
		digest := spcrypto.BodyDigestB64(plain)
		msg := spcrypto.RespMessage(ver, reqNonceB64, respTs, respNonceB64, digest)
		if c.opts.SignAlg == SignAlgEd25519 {
			sk := spcrypto.SafeB64Decode(keys.Ed25519SecretKeyServerB64)
			if sk == nil || len(sk) != 64 {
				return nil, "", newError(StatusServerError, "Secret key Ed25519 server tidak tersedia", nil)
			}
			sig, err := spcrypto.SignEd25519Detached([]byte(msg), sk)
			if err != nil {
				return nil, "", err
			}
			headers["X-Resp-Signature-Algorithm"] = spcrypto.Ed25519Alg
			headers["X-Resp-Signature"] = base64.StdEncoding.EncodeToString(sig)
		} else {
			if len(keys.HMACSecret) < 32 {
				return nil, "", newError(StatusServerError, "Secret Key HMAC response tidak tersedia di server", nil)
			}
			signKey := spcrypto.DeriveSubkey([]byte(keys.HMACSecret), spcrypto.KDFPurposeSignResp, c.opts.Version, c.opts.DeriveKeys)
			headers["X-Resp-Signature-Algorithm"] = spcrypto.HMACAlg
			headers["X-Resp-Signature"] = spcrypto.SignHMAC(msg, signKey)
		}
		headers["X-Resp-Body-Digest"] = "sha256=" + digest
	}

	return headers, bodyOut, nil
}

// VerifyResponse memverifikasi response (client-side) tanpa panic.
func (c *Client) VerifyResponse(headers map[string]string, rawBody, reqNonceB64 string) VerifyResult {
	data, err := c.VerifyResponseOrThrow(headers, rawBody, reqNonceB64)
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

// VerifyResponseOrThrow memverifikasi response dan mengembalikan error jika gagal.
func (c *Client) VerifyResponseOrThrow(headers map[string]string, rawBody, reqNonceB64 string) (*VerifyData, error) {
	if reqNonceB64 == "" {
		return nil, newError(StatusBadRequest, "Nonce request asal wajib diisi untuk verifikasi response", nil)
	}
	H := normalizeHeaders(headers)
	ver := H["X-RESP-SIGNATURE-VERSION"]
	respTs := H["X-RESP-TIMESTAMP"]
	respNonceB64 := H["X-RESP-NONCE"]

	if ver == "" || respTs == "" || respNonceB64 == "" {
		return nil, newError(StatusBadRequest, "Header response tidak lengkap", nil)
	}
	if ver != c.opts.Version {
		return nil, newError(StatusBadRequest, "Versi protokol response tidak didukung", nil)
	}
	if !digitsRe.MatchString(respTs) {
		return nil, newError(StatusBadRequest, "Format timestamp response salah", nil)
	}
	var ts int64
	_, _ = fmt.Sscanf(respTs, "%d", &ts)
	now := c.opts.Clock()
	if ts > now+int64(c.opts.ClockSkew) || ts < now-int64(c.opts.ReplayTTL+c.opts.ClockSkew) {
		return nil, newError(StatusUnauthorized, "Timestamp response di luar batas wajar", nil)
	}

	bodyForSig := rawBody

	if c.opts.Mode == ModeAEAD || c.opts.Mode == ModeBoth {
		if H["X-RESP-AEAD-ALGORITHM"] != spcrypto.AEADAlg {
			return nil, newError(StatusUnauthorized, fmt.Sprintf("Mode %s mewajibkan enkripsi AEAD pada response, namun header AEAD tidak ada/tidak dikenal", c.opts.Mode), nil)
		}
		var parsed map[string]string
		if err := json.Unmarshal([]byte(rawBody), &parsed); err != nil {
			return nil, newError(StatusBadRequest, "Payload AEAD response tidak ditemukan", nil)
		}
		blobB64 := parsed["__aead_b64"]
		if blobB64 == "" {
			return nil, newError(StatusBadRequest, "Payload AEAD response tidak ditemukan", nil)
		}
		raw := spcrypto.SafeB64Decode(c.opts.AEADKeyB64)
		if raw == nil || len(raw) != 32 {
			return nil, newError(StatusBadRequest, "Kunci AEAD client tidak valid/tersedia", nil)
		}
		key := spcrypto.DeriveSubkey(raw, spcrypto.KDFPurposeAeadResp, c.opts.Version, c.opts.DeriveKeys)
		nonceCalc := spcrypto.RespAeadNonceFrom(respNonceB64, reqNonceB64)
		nonceHdr := spcrypto.SafeB64Decode(H["X-RESP-AEAD-NONCE"])
		if nonceHdr == nil {
			nonceHdr = []byte{}
		}
		if subtle.ConstantTimeCompare(nonceHdr, nonceCalc) != 1 {
			return nil, newError(StatusUnauthorized, "Nonce response mismatch (integritas invalid)", nil)
		}
		ct := spcrypto.SafeB64Decode(blobB64)
		if ct == nil {
			return nil, newError(StatusBadRequest, "Format base64 body response rusak", nil)
		}
		aad := []byte(spcrypto.BuildResponseAeadAad(ver, reqNonceB64, respTs))
		plain, err := spcrypto.DecryptAEAD(key, nonceCalc, aad, ct)
		if err != nil {
			return nil, newError(StatusUnauthorized, "Gagal mendekripsi response (kunci salah atau data rusak)", nil)
		}
		bodyForSig = string(plain)
		if c.opts.Mode == ModeAEAD {
			var j interface{}
			_ = json.Unmarshal(plain, &j)
			return &VerifyData{Mode: "AEAD", BodyPlain: bodyForSig, JSON: j}, nil
		}
	}

	if c.opts.Mode == ModeHMAC || c.opts.Mode == ModeBoth {
		expectedAlg := spcrypto.HMACAlg
		if c.opts.SignAlg == SignAlgEd25519 {
			expectedAlg = spcrypto.Ed25519Alg
		}
		alg := H["X-RESP-SIGNATURE-ALGORITHM"]
		sigIn := H["X-RESP-SIGNATURE"]
		dig := H["X-RESP-BODY-DIGEST"]
		if alg != expectedAlg || sigIn == "" || dig == "" {
			return nil, newError(StatusBadRequest, "Header tanda tangan response tidak lengkap/salah algoritma", nil)
		}
		digVal := strings.TrimPrefix(dig, "sha256=")
		if digVal == dig {
			return nil, newError(StatusBadRequest, "Format digest response salah (harus sha256=...)", nil)
		}
		calc := spcrypto.BodyDigestB64(bodyForSig)
		if subtle.ConstantTimeCompare([]byte(digVal), []byte(calc)) != 1 {
			return nil, newError(StatusUnprocessable, "Integritas Body Digest response gagal", nil)
		}
		msg := spcrypto.RespMessage(c.opts.Version, reqNonceB64, respTs, respNonceB64, calc)
		if c.opts.SignAlg == SignAlgEd25519 {
			pub := spcrypto.SafeB64Decode(c.opts.Ed25519PublicKeyServerB64)
			if pub == nil || len(pub) != 32 {
				return nil, newError(StatusBadRequest, "Public key Ed25519 server tidak valid/tersedia di client", nil)
			}
			sig := spcrypto.SafeB64Decode(sigIn)
			if sig == nil || len(sig) != 64 {
				return nil, newError(StatusBadRequest, "Format signature Ed25519 response rusak", nil)
			}
			if !spcrypto.VerifyEd25519Detached([]byte(msg), sig, pub) {
				return nil, newError(StatusUnauthorized, "Tanda Tangan response (Ed25519) tidak valid", nil)
			}
		} else {
			if len(c.opts.HMACSecretRaw) < 32 {
				return nil, newError(StatusBadRequest, "HMAC secret client tidak valid/tersedia", nil)
			}
			signKey := spcrypto.DeriveSubkey([]byte(c.opts.HMACSecretRaw), spcrypto.KDFPurposeSignResp, c.opts.Version, c.opts.DeriveKeys)
			if subtle.ConstantTimeCompare([]byte(spcrypto.SignHMAC(msg, signKey)), []byte(sigIn)) != 1 {
				return nil, newError(StatusUnauthorized, "Tanda Tangan response (HMAC) tidak valid", nil)
			}
		}
		mode := "HMAC"
		if c.opts.Mode == ModeBoth {
			mode = "BOTH"
		}
		var j interface{}
		_ = json.Unmarshal([]byte(bodyForSig), &j)
		return &VerifyData{Mode: mode, BodyPlain: bodyForSig, JSON: j}, nil
	}

	return nil, newError(StatusBadRequest, "Header response tidak lengkap", nil)
}
