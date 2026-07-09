package conformance_test

import (
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/sk8dvlpr/securepayload-go/securepayload"
	spcrypto "github.com/sk8dvlpr/securepayload-go/securepayload/crypto"
	"github.com/sk8dvlpr/securepayload-go/testutil"
)

func TestPrimitiveNormalizePath(t *testing.T) {
	var vector struct {
		Cases []struct {
			Input    string `json:"input"`
			Expected string `json:"expected"`
		} `json:"cases"`
	}
	if err := testutil.LoadJSON(filepath.Join(testutil.FixturesRoot(), "primitive", "normalize-path.json"), &vector); err != nil {
		t.Fatal(err)
	}
	for _, c := range vector.Cases {
		if got := spcrypto.NormalizePath(c.Input); got != c.Expected {
			t.Fatalf("normalizePath(%q) = %q, want %q", c.Input, got, c.Expected)
		}
	}
}

func TestPrimitiveCanonicalQuery(t *testing.T) {
	var vector struct {
		Cases []struct {
			Input    json.RawMessage `json:"input"`
			Expected string          `json:"expected"`
		} `json:"cases"`
	}
	if err := testutil.LoadJSON(filepath.Join(testutil.FixturesRoot(), "primitive", "canonical-query.json"), &vector); err != nil {
		t.Fatal(err)
	}
	for _, c := range vector.Cases {
		var input map[string]interface{}
		if len(c.Input) > 0 && c.Input[0] == '[' {
			if string(c.Input) != "[]" {
				t.Fatalf("unexpected array input: %s", c.Input)
			}
			input = map[string]interface{}{}
		} else if err := json.Unmarshal(c.Input, &input); err != nil {
			t.Fatal(err)
		}
		if got := spcrypto.CanonicalQuery(input); got != c.Expected {
			t.Fatalf("canonicalQuery(%v) = %q, want %q", input, got, c.Expected)
		}
	}
}

func TestPrimitiveBodyDigest(t *testing.T) {
	var vector struct {
		Input struct {
			JSON string `json:"json"`
		} `json:"input"`
		Expected struct {
			DigestB64 string `json:"digest_b64"`
		} `json:"expected"`
	}
	if err := testutil.LoadJSON(filepath.Join(testutil.FixturesRoot(), "primitive", "body-digest.json"), &vector); err != nil {
		t.Fatal(err)
	}
	if got := spcrypto.BodyDigestB64(vector.Input.JSON); got != vector.Expected.DigestB64 {
		t.Fatalf("bodyDigest = %q, want %q", got, vector.Expected.DigestB64)
	}
}

func TestPrimitiveMessagesAndNonces(t *testing.T) {
	var hmacVec struct {
		Input struct {
			Version       string                 `json:"version"`
			ClientID      string                 `json:"clientId"`
			KeyID         string                 `json:"keyId"`
			Timestamp     string                 `json:"timestamp"`
			NonceB64      string                 `json:"nonce_b64"`
			Method        string                 `json:"method"`
			Path          string                 `json:"path"`
			Query         map[string]interface{} `json:"query"`
			BodyDigestB64 string                 `json:"body_digest_b64"`
		} `json:"input"`
		Expected struct {
			Message string `json:"message"`
		} `json:"expected"`
	}
	if err := testutil.LoadJSON(filepath.Join(testutil.FixturesRoot(), "primitive", "hmac-message.json"), &hmacVec); err != nil {
		t.Fatal(err)
	}
	q := spcrypto.CanonicalQuery(hmacVec.Input.Query)
	got := spcrypto.HMACMessage(hmacVec.Input.Version, hmacVec.Input.ClientID, hmacVec.Input.KeyID,
		hmacVec.Input.Timestamp, hmacVec.Input.NonceB64, hmacVec.Input.Method, hmacVec.Input.Path, q, hmacVec.Input.BodyDigestB64)
	if got != hmacVec.Expected.Message {
		t.Fatalf("hmacMessage mismatch:\n%q\nvs\n%q", got, hmacVec.Expected.Message)
	}

	var respVec struct {
		Input struct {
			Version       string `json:"version"`
			ReqNonceB64   string `json:"req_nonce_b64"`
			RespTimestamp string `json:"resp_timestamp"`
			RespNonceB64  string `json:"resp_nonce_b64"`
			BodyDigestB64 string `json:"body_digest_b64"`
		} `json:"input"`
		Expected struct {
			Message string `json:"message"`
		} `json:"expected"`
	}
	if err := testutil.LoadJSON(filepath.Join(testutil.FixturesRoot(), "primitive", "resp-message.json"), &respVec); err != nil {
		t.Fatal(err)
	}
	gotResp := spcrypto.RespMessage(respVec.Input.Version, respVec.Input.ReqNonceB64, respVec.Input.RespTimestamp,
		respVec.Input.RespNonceB64, respVec.Input.BodyDigestB64)
	if gotResp != respVec.Expected.Message {
		t.Fatalf("respMessage mismatch")
	}

	var nonceReq struct {
		Input struct {
			NonceB64    string `json:"nonce_b64"`
			Method      string `json:"method"`
			Path        string `json:"path"`
			QueryString string `json:"query_string"`
		} `json:"input"`
		Expected struct {
			NonceHex string `json:"nonce_hex"`
		} `json:"expected"`
	}
	if err := testutil.LoadJSON(filepath.Join(testutil.FixturesRoot(), "primitive", "aead-nonce-request.json"), &nonceReq); err != nil {
		t.Fatal(err)
	}
	nonce := spcrypto.AeadNonceFrom(nonceReq.Input.NonceB64, nonceReq.Input.Method, nonceReq.Input.Path, nonceReq.Input.QueryString)
	if hex.EncodeToString(nonce) != nonceReq.Expected.NonceHex {
		t.Fatalf("aead nonce req: got %s want %s", hex.EncodeToString(nonce), nonceReq.Expected.NonceHex)
	}

	var nonceResp struct {
		Input struct {
			RespNonceB64 string `json:"resp_nonce_b64"`
			ReqNonceB64  string `json:"req_nonce_b64"`
		} `json:"input"`
		Expected struct {
			NonceHex string `json:"nonce_hex"`
		} `json:"expected"`
	}
	if err := testutil.LoadJSON(filepath.Join(testutil.FixturesRoot(), "primitive", "resp-aead-nonce.json"), &nonceResp); err != nil {
		t.Fatal(err)
	}
	rn := spcrypto.RespAeadNonceFrom(nonceResp.Input.RespNonceB64, nonceResp.Input.ReqNonceB64)
	if hex.EncodeToString(rn) != nonceResp.Expected.NonceHex {
		t.Fatalf("resp aead nonce: got %s want %s", hex.EncodeToString(rn), nonceResp.Expected.NonceHex)
	}
}

func TestPrimitiveAADAndHKDF(t *testing.T) {
	var aadVec struct {
		Input struct {
			Version      string            `json:"version"`
			Timestamp    string            `json:"timestamp"`
			BoundHeaders map[string]string `json:"bound_headers"`
		} `json:"input"`
		Expected struct {
			AAD string `json:"aad"`
		} `json:"expected"`
	}
	if err := testutil.LoadJSON(filepath.Join(testutil.FixturesRoot(), "primitive", "aead-aad-request.json"), &aadVec); err != nil {
		t.Fatal(err)
	}
	if got := spcrypto.BuildRequestAeadAad(aadVec.Input.Version, aadVec.Input.Timestamp, aadVec.Input.BoundHeaders); got != aadVec.Expected.AAD {
		t.Fatalf("aad mismatch: %q vs %q", got, aadVec.Expected.AAD)
	}

	var hkdfVec struct {
		Cases []struct {
			Master      string `json:"master"`
			Purpose     string `json:"purpose"`
			ExpectedHex string `json:"expected_hex"`
		} `json:"cases"`
	}
	if err := testutil.LoadJSON(filepath.Join(testutil.FixturesRoot(), "primitive", "hkdf-derive.json"), &hkdfVec); err != nil {
		t.Fatal(err)
	}
	for _, c := range hkdfVec.Cases {
		purpose := c.Purpose
		if idx := len(purpose); idx > 0 {
			for i, ch := range c.Purpose {
				if ch == '|' {
					purpose = c.Purpose[:i]
					break
				}
			}
		}
		out := spcrypto.DeriveSubkey([]byte(c.Master), purpose, "3", true)
		if hex.EncodeToString(out) != c.ExpectedHex {
			t.Fatalf("hkdf %s: got %s want %s", c.Purpose, hex.EncodeToString(out), c.ExpectedHex)
		}
	}
}

func loadStandardKeys(t *testing.T) map[string]string {
	t.Helper()
	var keys map[string]string
	if err := testutil.LoadJSON(filepath.Join(testutil.FixturesRoot(), "keys", "standard.json"), &keys); err != nil {
		t.Fatal(err)
	}
	return keys
}

func makeClientOpts(keys map[string]string, vector map[string]interface{}, fixed map[string]interface{}) securepayload.Options {
	config := vector["config"].(map[string]interface{})
	protocolVersion, _ := vector["protocol_version"].(string)
	signAlg := securepayload.SignAlgHMAC
	if sa, ok := config["signAlg"].(string); ok && sa == "ed25519" {
		signAlg = securepayload.SignAlgEd25519
	}
	deriveKeys := false
	if dk, ok := config["deriveKeys"].(bool); ok {
		deriveKeys = dk
	}
	var bindHeaders []string
	if bh, ok := config["bindHeaders"].([]interface{}); ok {
		for _, item := range bh {
			if s, ok := item.(string); ok {
				bindHeaders = append(bindHeaders, s)
			}
		}
	}
	ts := int64(fixed["timestamp"].(float64))
	opts := securepayload.Options{
		Mode:                      securepayload.Mode(config["mode"].(string)),
		SignAlg:                   signAlg,
		Version:                   protocolVersion,
		ClientID:                  keys["clientId"],
		KeyID:                     keys["keyId"],
		HMACSecretRaw:             keys["hmacSecret"],
		AEADKeyB64:                keys["aeadKeyB64"],
		Ed25519SecretKeyB64:       keys["ed25519ClientSecretB64"],
		Ed25519PublicKeyServerB64: keys["ed25519ServerPublicB64"],
		DeriveKeys:                deriveKeys,
		BindHeaders:               bindHeaders,
		Clock:                     func() int64 { return ts },
		NonceGen:                  func() string { return fixed["nonce_b64"].(string) },
		RespNonceGen:              func() string { return fixed["resp_nonce_b64"].(string) },
		ReplayStore:               func(string, int) bool { return true },
		KeyLoader: func(string, string) securepayload.LoadedKeys {
			return securepayload.LoadedKeys{
				HMACSecret:                keys["hmacSecret"],
				AEADKeyB64:                keys["aeadKeyB64"],
				Ed25519PublicKeyB64:       keys["ed25519ClientPublicB64"],
				Ed25519SecretKeyServerB64: keys["ed25519ServerSecretB64"],
				Ed25519PublicKeyServerB64: keys["ed25519ServerPublicB64"],
			}
		},
	}
	return opts
}
