package securepayload

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"time"

	spcrypto "github.com/sk8dvlpr/securepayload-go/securepayload/crypto"
)

type Client struct {
	opts Options
}

func New(opts Options) *Client {
	return &Client{opts: opts.withDefaults()}
}

func unixNow() int64 {
	return time.Now().Unix()
}

func genNonceB64() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func jsonEncode(v interface{}) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func aeadBody(b64 string) (string, error) {
	return jsonEncode(map[string]string{"__aead_b64": b64})
}

func normalizeHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		out[strings.ToUpper(k)] = v
	}
	return out
}

func collectBoundHeaders(all map[string]string, bindHeaders []string) map[string]string {
	norm := make(map[string]string, len(all))
	for k, v := range all {
		norm[strings.ToLower(k)] = v
	}
	out := make(map[string]string, len(bindHeaders))
	for _, h := range bindHeaders {
		lname := strings.ToLower(h)
		out[lname] = norm[lname]
	}
	return out
}

func parseQueryInput(query interface{}) map[string]interface{} {
	switch q := query.(type) {
	case map[string]interface{}:
		return q
	case map[string]string:
		out := make(map[string]interface{}, len(q))
		for k, v := range q {
			out[k] = v
		}
		return out
	case string:
		vals, _ := url.ParseQuery(q)
		out := make(map[string]interface{}, len(vals))
		for k, v := range vals {
			if len(v) == 1 {
				out[k] = v[0]
			} else {
				arr := make([]interface{}, len(v))
				for i, item := range v {
					arr[i] = item
				}
				out[k] = arr
			}
		}
		return out
	default:
		return map[string]interface{}{}
	}
}

var digitsRe = regexp.MustCompile(`^\d+$`)

func (c *Client) resolveKeys(clientID, keyID string) LoadedKeys {
	if c.opts.KeyLoader != nil {
		return c.opts.KeyLoader(clientID, keyID)
	}
	return LoadedKeys{
		HMACSecret:                c.opts.HMACSecretRaw,
		AEADKeyB64:                c.opts.AEADKeyB64,
		Ed25519PublicKeyB64:       c.opts.Ed25519PublicKeyB64,
		Ed25519SecretKeyServerB64: c.opts.Ed25519SecretKeyServerB64,
		Ed25519PublicKeyServerB64: c.opts.Ed25519PublicKeyServerB64,
	}
}

func (c *Client) signCanonical(message string, scope string) (sigB64, alg string, err error) {
	if c.opts.SignAlg == SignAlgEd25519 {
		var secretB64 string
		if scope == "req" {
			secretB64 = c.opts.Ed25519SecretKeyB64
		} else {
			secretB64 = c.opts.Ed25519SecretKeyServerB64
		}
		sk := spcrypto.SafeB64Decode(secretB64)
		if sk == nil || len(sk) != 64 {
			return "", "", newError(StatusBadRequest, "Secret key Ed25519 tidak valid", nil)
		}
		sig, err := spcrypto.SignEd25519Detached([]byte(message), sk)
		if err != nil {
			return "", "", err
		}
		return base64.StdEncoding.EncodeToString(sig), spcrypto.Ed25519Alg, nil
	}
	master := []byte(c.opts.HMACSecretRaw)
	if len(master) < 32 {
		return "", "", newError(StatusBadRequest, "HMAC Secret terlalu pendek. Minimum 32 karakter.", nil)
	}
	purpose := spcrypto.KDFPurposeSignReq
	if scope == "resp" {
		purpose = spcrypto.KDFPurposeSignResp
	}
	key := spcrypto.DeriveSubkey(master, purpose, c.opts.Version, c.opts.DeriveKeys)
	return spcrypto.SignHMAC(message, key), spcrypto.HMACAlg, nil
}
