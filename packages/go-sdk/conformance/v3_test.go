package conformance_test

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/sk8dvlpr/securepayload-go/securepayload"
	"github.com/sk8dvlpr/securepayload-go/testutil"
)

func makeURL(req map[string]interface{}) string {
	path, _ := req["path"].(string)
	query, _ := req["query"].(map[string]interface{})
	q := url.Values{}
	for k, v := range query {
		switch t := v.(type) {
		case string:
			q.Set(k, t)
		case float64:
			q.Set(k, fmt.Sprintf("%.0f", t))
		default:
			q.Set(k, fmt.Sprint(v))
		}
	}
	return "https://example.test" + path + "?" + q.Encode()
}

func extraHeaders(req map[string]interface{}) map[string]string {
	raw := req["extra_headers"]
	if raw == nil {
		return map[string]string{}
	}
	if arr, ok := raw.([]interface{}); ok {
		if len(arr) == 0 {
			return map[string]string{}
		}
	}
	if m, ok := raw.(map[string]interface{}); ok {
		out := make(map[string]string, len(m))
		for k, v := range m {
			out[k] = fmt.Sprint(v)
		}
		return out
	}
	return map[string]string{}
}

func makeServerOpts(keys map[string]string, vector map[string]interface{}) securepayload.Options {
	config := vector["config"].(map[string]interface{})
	protocolVersion, _ := vector["protocol_version"].(string)
	fixed := vector["fixed"].(map[string]interface{})

	signAlg := securepayload.SignAlgHMAC
	if sc, ok := vector["server_config"].(map[string]interface{}); ok {
		if sa, ok := sc["signAlg"].(string); ok && sa == "ed25519" {
			signAlg = securepayload.SignAlgEd25519
		}
	} else if sa, ok := config["signAlg"].(string); ok && sa == "ed25519" {
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
	return securepayload.Options{
		Mode:         securepayload.Mode(config["mode"].(string)),
		SignAlg:      signAlg,
		Version:      protocolVersion,
		DeriveKeys:   deriveKeys,
		BindHeaders:  bindHeaders,
		Clock:        func() int64 { return ts },
		ReplayStore:  func(string, int) bool { return true },
		RespNonceGen: func() string { return fixed["resp_nonce_b64"].(string) },
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
}

func makeResponseOpts(keys map[string]string, vector map[string]interface{}) securepayload.Options {
	config := vector["config"].(map[string]interface{})
	protocolVersion, _ := vector["protocol_version"].(string)
	fixed := vector["fixed"].(map[string]interface{})

	signAlg := securepayload.SignAlgHMAC
	if sa, ok := config["signAlg"].(string); ok && sa == "ed25519" {
		signAlg = securepayload.SignAlgEd25519
	}
	deriveKeys := false
	if dk, ok := config["deriveKeys"].(bool); ok {
		deriveKeys = dk
	}
	respTs := int64(fixed["resp_timestamp"].(float64))
	return securepayload.Options{
		Mode:                      securepayload.Mode(config["mode"].(string)),
		SignAlg:                   signAlg,
		Version:                   protocolVersion,
		ClientID:                  keys["clientId"],
		KeyID:                     keys["keyId"],
		HMACSecretRaw:             keys["hmacSecret"],
		AEADKeyB64:                keys["aeadKeyB64"],
		Ed25519SecretKeyServerB64: keys["ed25519ServerSecretB64"],
		Ed25519PublicKeyServerB64: keys["ed25519ServerPublicB64"],
		DeriveKeys:                deriveKeys,
		Clock:                     func() int64 { return respTs },
		RespNonceGen:              func() string { return fixed["resp_nonce_b64"].(string) },
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
}

func assertHeadersEqual(t *testing.T, got, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("header %s: got %q want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("header count: got %d want %d (got keys: %v)", len(got), len(want), mapKeys(got))
	}
}

func mapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func TestWireConformance(t *testing.T) {
	keys := loadStandardKeys(t)
	files, err := testutil.ListJSONFiles("wire")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		name := filepath.Base(file)
		t.Run(name, func(t *testing.T) {
			var vector map[string]interface{}
			if err := testutil.LoadJSON(file, &vector); err != nil {
				t.Fatal(err)
			}
			req := vector["request"].(map[string]interface{})
			expected := vector["expected"].(map[string]interface{})
			expHeaders := map[string]string{}
			for k, v := range expected["headers"].(map[string]interface{}) {
				expHeaders[k] = v.(string)
			}
			expBody := expected["body"].(string)

			client := securepayload.New(makeClientOpts(keys, vector, vector["fixed"].(map[string]interface{})))
			headers, body, err := client.BuildHeadersAndBody(
				makeURL(req),
				req["method"].(string),
				req["payload"].(map[string]interface{}),
				extraHeaders(req),
			)
			if err != nil {
				t.Fatalf("BuildHeadersAndBody: %v", err)
			}
			assertHeadersEqual(t, headers, expHeaders)
			if body != expBody {
				t.Fatalf("body mismatch:\ngot:  %q\nwant: %q", body, expBody)
			}

			server := securepayload.New(makeServerOpts(keys, vector))
			verified := server.Verify(expHeaders, expBody, req["method"].(string), req["path"].(string), req["query"])
			if !verified.OK {
				t.Fatalf("verify failed: %s (status %d)", verified.Error, verified.Status)
			}

			if respRaw, ok := expected["response"]; ok {
				respExp := respRaw.(map[string]interface{})
				respPayload := respExp["payload"].(map[string]interface{})
				respHeadersExp := map[string]string{}
				for k, v := range respExp["headers"].(map[string]interface{}) {
					respHeadersExp[k] = v.(string)
				}
				respBodyExp := respExp["body"].(string)

				responseNode := securepayload.New(makeResponseOpts(keys, vector))
				respHeaders, respBody, err := responseNode.BuildResponse(expHeaders, respPayload)
				if err != nil {
					t.Fatalf("BuildResponse: %v", err)
				}
				assertHeadersEqual(t, respHeaders, respHeadersExp)
				if respBody != respBodyExp {
					t.Fatalf("response body mismatch:\ngot:  %q\nwant: %q", respBody, respBodyExp)
				}

				fixed := vector["fixed"].(map[string]interface{})
				clientVerify := responseNode.VerifyResponse(respHeadersExp, respBodyExp, fixed["nonce_b64"].(string))
				if !clientVerify.OK {
					t.Fatalf("verifyResponse failed: %s", clientVerify.Error)
				}
			}
		})
	}
}

func TestNegativeVectors(t *testing.T) {
	keys := loadStandardKeys(t)
	files, err := testutil.ListJSONFiles("negative")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		name := filepath.Base(file)
		t.Run(name, func(t *testing.T) {
			var vector map[string]interface{}
			if err := testutil.LoadJSON(file, &vector); err != nil {
				t.Fatal(err)
			}
			req := vector["request"].(map[string]interface{})
			expected := vector["expected"].(map[string]interface{})
			expHeaders := map[string]string{}
			for k, v := range expected["headers"].(map[string]interface{}) {
				expHeaders[k] = v.(string)
			}
			expBody := expected["body"].(string)

			server := securepayload.New(makeServerOpts(keys, vector))
			out := server.Verify(expHeaders, expBody, req["method"].(string), req["path"].(string), req["query"])
			if out.OK {
				t.Fatal("expected verify to fail")
			}
			if out.Status != 400 && out.Status != 401 {
				t.Fatalf("expected status 400 or 401, got %d: %s", out.Status, out.Error)
			}
		})
	}
}

func TestMain(m *testing.M) {
	if _, err := os.Stat(testutil.FixturesRoot()); err != nil {
		fmt.Fprintf(os.Stderr, "fixtures not found at %s\n", testutil.FixturesRoot())
		os.Exit(1)
	}
	os.Exit(m.Run())
}
