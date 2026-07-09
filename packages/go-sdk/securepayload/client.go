package securepayload

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	spcrypto "github.com/sk8dvlpr/securepayload-go/securepayload/crypto"
)

// BuildHeadersAndBody membangun header keamanan dan body request (client-side).
func (c *Client) BuildHeadersAndBody(rawURL, method string, payload map[string]interface{}, extraHeaders map[string]string) (map[string]string, string, error) {
	if c.opts.ClientID == "" || c.opts.KeyID == "" {
		return nil, "", newError(StatusBadRequest, "clientId & keyId wajib diisi untuk mode client", nil)
	}
	if extraHeaders == nil {
		extraHeaders = map[string]string{}
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, "", newError(StatusBadRequest, "Format URL tidak valid", nil)
	}

	m := strings.ToUpper(method)
	path := spcrypto.NormalizePath(parsed.Path)
	if path == "" {
		path = "/"
	}
	qObj := map[string]interface{}{}
	for k, vals := range parsed.Query() {
		if len(vals) == 1 {
			qObj[k] = vals[0]
		} else {
			arr := make([]interface{}, len(vals))
			for i, v := range vals {
				arr[i] = v
			}
			qObj[k] = arr
		}
	}
	qStr := spcrypto.CanonicalQuery(qObj)
	ts := fmt.Sprintf("%d", c.opts.Clock())
	nonceB64 := c.opts.NonceGen()

	headers := make(map[string]string, len(extraHeaders)+8)
	for k, v := range extraHeaders {
		headers[k] = v
	}
	headers["X-Client-Id"] = c.opts.ClientID
	headers["X-Key-Id"] = c.opts.KeyID
	headers["X-Timestamp"] = ts
	headers["X-Nonce"] = nonceB64
	headers["X-Signature-Version"] = c.opts.Version
	headers["X-Canonical-Request"] = base64.StdEncoding.EncodeToString([]byte(m + "\n" + path + "\n" + qStr))

	bound := collectBoundHeaders(extraHeaders, c.opts.BindHeaders)

	if c.opts.Mode == ModeAEAD || c.opts.Mode == ModeBoth {
		plain, err := jsonEncode(payload)
		if err != nil {
			return nil, "", newError(StatusBadRequest, "Gagal encode JSON payload", nil)
		}
		rawKey := spcrypto.SafeB64Decode(c.opts.AEADKeyB64)
		if rawKey == nil || len(rawKey) != 32 {
			return nil, "", newError(StatusBadRequest, "AEAD key tidak valid", nil)
		}
		key := spcrypto.DeriveSubkey(rawKey, spcrypto.KDFPurposeAeadReq, c.opts.Version, c.opts.DeriveKeys)
		nonce := spcrypto.AeadNonceFrom(nonceB64, m, path, qStr)
		aad := []byte(spcrypto.BuildRequestAeadAad(c.opts.Version, ts, bound))
		ct, err := spcrypto.EncryptAEAD(key, nonce, aad, []byte(plain))
		if err != nil {
			return nil, "", newError(StatusBadRequest, "Gagal enkripsi AEAD", nil)
		}
		headers["X-AEAD-Algorithm"] = spcrypto.AEADAlg
		headers["X-AEAD-Nonce"] = base64.StdEncoding.EncodeToString(nonce)
		wrapped, err := aeadBody(base64.StdEncoding.EncodeToString(ct))
		if err != nil {
			return nil, "", err
		}
		if c.opts.Mode == ModeAEAD {
			return headers, wrapped, nil
		}
		digest := spcrypto.BodyDigestB64(plain)
		msg := spcrypto.HMACMessage(c.opts.Version, c.opts.ClientID, c.opts.KeyID, ts, nonceB64, m, path, qStr, digest)
		sig, alg, err := c.signCanonical(msg, "req")
		if err != nil {
			return nil, "", err
		}
		headers["X-Signature-Algorithm"] = alg
		headers["X-Body-Digest"] = "sha256=" + digest
		headers["X-Signature"] = sig
		return headers, wrapped, nil
	}

	plain, err := jsonEncode(payload)
	if err != nil {
		return nil, "", newError(StatusBadRequest, "Gagal encode JSON payload", nil)
	}
	digest := spcrypto.BodyDigestB64(plain)
	msg := spcrypto.HMACMessage(c.opts.Version, c.opts.ClientID, c.opts.KeyID, ts, nonceB64, m, path, qStr, digest)
	sig, alg, err := c.signCanonical(msg, "req")
	if err != nil {
		return nil, "", err
	}
	headers["X-Signature-Algorithm"] = alg
	headers["X-Body-Digest"] = "sha256=" + digest
	headers["X-Signature"] = sig
	return headers, plain, nil
}
