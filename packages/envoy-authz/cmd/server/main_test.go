package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sp "github.com/sk8dvlpr/securepayload-go/securepayload"
)

const testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// authResponse adalah bentuk JSON respons service ext_authz.
type authResponse struct {
	Decision string `json:"decision"`
	Status   int    `json:"status"`
	Mode     string `json:"mode"`
	Error    string `json:"error"`
}

// testConfig membuat Config dasar untuk pengujian (single-secret, HMAC).
func testConfig(mutate func(*Config)) *Config {
	cfg := &Config{
		ListenAddr:   ":0",
		Mode:         sp.ModeHMAC,
		SignAlg:      sp.SignAlgHMAC,
		Version:      sp.DefaultVersion,
		ReplayTTL:    120,
		ClockSkew:    60,
		MaxBodyBytes: 1 << 20,
		Clock:        func() int64 { return time.Now().Unix() },
		single:       true,
		solo:         sp.LoadedKeys{HMACSecret: testSecret},
	}
	if mutate != nil {
		mutate(cfg)
	}
	return cfg
}

func newTestServer(t *testing.T, cfg *Config) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(newServer(cfg, newMemoryReplayStore(1000)))
	t.Cleanup(srv.Close)
	return srv
}

// signHMAC membangun header+body ter-tanda-tangan menggunakan go-sdk (bukan
// kripto buatan tangan) — sama seperti klien asli.
func signHMAC(t *testing.T, rawURL, method string, payload map[string]interface{}) (map[string]string, string) {
	t.Helper()
	client := sp.New(sp.Options{
		Mode:          sp.ModeHMAC,
		Version:       sp.DefaultVersion,
		ClientID:      "c1",
		KeyID:         "k1",
		HMACSecretRaw: testSecret,
	})
	headers, body, err := client.BuildHeadersAndBody(rawURL, method, payload, nil)
	if err != nil {
		t.Fatalf("gagal menandatangani request: %v", err)
	}
	return headers, body
}

// post mengirim request mentah ke server uji dan mengurai respons JSON.
func post(t *testing.T, ts *httptest.Server, path string, headers map[string]string, body []byte) (*http.Response, authResponse) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out authResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("respons bukan JSON: %v", err)
	}
	return resp, out
}

// checkRequestBody membungkus atribut menjadi CheckRequest JSON (proto3 JSON).
func checkRequestBody(t *testing.T, headers map[string]string, method, fullPath, body string) []byte {
	t.Helper()
	cr := checkRequest{}
	cr.Attributes.Request.HTTP = httpAttrs{Headers: headers, Method: method, Path: fullPath, Body: body}
	out, err := json.Marshal(cr)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestHealthz(t *testing.T) {
	ts := newTestServer(t, testConfig(nil))
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status=%d want 200", resp.StatusCode)
	}
	var out map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out["status"] != "ok" {
		t.Fatalf("healthz body tidak sesuai: %v %v", out, err)
	}
}

// TestAllowRawMirrorHMAC mensimulasikan mode http_service Envoy: request asli
// di-mirror apa adanya ke service authz.
func TestAllowRawMirrorHMAC(t *testing.T) {
	ts := newTestServer(t, testConfig(nil))
	headers, body := signHMAC(t, "http://upstream.test/v4?a=1&b=2", "POST", map[string]interface{}{"hello": "world"})

	resp, got := post(t, ts, "/v4?a=1&b=2", headers, []byte(body))
	if resp.StatusCode != http.StatusOK || got.Decision != "allow" {
		t.Fatalf("status=%d decision=%s error=%s", resp.StatusCode, got.Decision, got.Error)
	}
	if !strings.EqualFold(got.Mode, "HMAC") {
		t.Fatalf("mode=%s want HMAC", got.Mode)
	}
}

// TestAllowCheckRequestJSON memastikan bentuk CheckRequest JSON (mode gRPC /
// bridge JSON) juga diverifikasi dengan benar, termasuk pemisahan query dari path.
func TestAllowCheckRequestJSON(t *testing.T) {
	ts := newTestServer(t, testConfig(nil))
	headers, body := signHMAC(t, "http://upstream.test/v4?a=1", "POST", map[string]interface{}{"hello": "world"})

	resp, got := post(t, ts, "/authz/v4", nil, checkRequestBody(t, headers, "POST", "/v4?a=1", body))
	if resp.StatusCode != http.StatusOK || got.Decision != "allow" {
		t.Fatalf("status=%d decision=%s error=%s", resp.StatusCode, got.Decision, got.Error)
	}
}

// TestDenyTamperedSignature: tanda tangan yang dimodifikasi harus ditolak 401,
// dan secret tidak boleh bocor ke respons.
func TestDenyTamperedSignature(t *testing.T) {
	ts := newTestServer(t, testConfig(nil))
	headers, body := signHMAC(t, "http://upstream.test/v4", "POST", map[string]interface{}{"hello": "world"})
	headers["X-Signature"] = strings.Repeat("A", len(headers["X-Signature"]))

	resp, got := post(t, ts, "/v4", headers, []byte(body))
	if resp.StatusCode != http.StatusUnauthorized || got.Decision != "deny" {
		t.Fatalf("status=%d decision=%s want 403/deny", resp.StatusCode, got.Decision)
	}
	if strings.Contains(got.Error, testSecret) {
		t.Fatal("secret bocor pada pesan error")
	}
}

// TestDenyMissingSecurityHeader: header keamanan hilang → 400 deny.
func TestDenyMissingSecurityHeader(t *testing.T) {
	ts := newTestServer(t, testConfig(nil))
	headers, body := signHMAC(t, "http://upstream.test/v4", "POST", map[string]interface{}{"hello": "world"})
	delete(headers, "X-Client-Id")

	resp, got := post(t, ts, "/v4", headers, []byte(body))
	if resp.StatusCode != http.StatusBadRequest || got.Decision != "deny" {
		t.Fatalf("status=%d decision=%s want 400/deny", resp.StatusCode, got.Decision)
	}
}

// TestDenyUnknownClientMultiKey: mode SP_KEYS_JSON menolak pasangan
// clientId/keyId yang tidak terdaftar dengan 401.
func TestDenyUnknownClientMultiKey(t *testing.T) {
	keysJSON := fmt.Sprintf(`{"c1|k1":{"secret":%q}}`, testSecret)
	cfg := testConfig(func(c *Config) { c.single = false })
	if err := cfg.loadKeysJSON(keysJSON); err != nil {
		t.Fatal(err)
	}
	ts := newTestServer(t, cfg)

	headers, body := signHMAC(t, "http://upstream.test/v4", "POST", map[string]interface{}{"hello": "world"})
	headers["X-Key-Id"] = "k-other"

	resp, got := post(t, ts, "/v4", headers, []byte(body))
	if resp.StatusCode != http.StatusUnauthorized || got.Decision != "deny" {
		t.Fatalf("status=%d decision=%s want 401/deny", resp.StatusCode, got.Decision)
	}
}

// TestDenyReplaySecondRequest: request identik kedua harus ditolak (replay).
func TestDenyReplaySecondRequest(t *testing.T) {
	ts := newTestServer(t, testConfig(nil))
	headers, body := signHMAC(t, "http://upstream.test/v4", "POST", map[string]interface{}{"n": 1})

	resp1, _ := post(t, ts, "/v4", headers, []byte(body))
	resp2, got2 := post(t, ts, "/v4", headers, []byte(body))
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("request pertama harus allow, dapat %d", resp1.StatusCode)
	}
	if resp2.StatusCode != http.StatusUnauthorized || got2.Decision != "deny" {
		t.Fatalf("replay status=%d decision=%s want 401/deny", resp2.StatusCode, got2.Decision)
	}
}

// TestFailClosedOnInvalidRawBodyBase64: raw_body rusak pada CheckRequest →
// 500 fail-closed (Envoy akan menolak request karena failure_mode_allow=false).
func TestFailClosedOnInvalidRawBodyBase64(t *testing.T) {
	ts := newTestServer(t, testConfig(nil))
	headers, _ := signHMAC(t, "http://upstream.test/v4", "POST", map[string]interface{}{"hello": "world"})

	cr := checkRequest{}
	cr.Attributes.Request.HTTP = httpAttrs{Headers: headers, Method: "POST", Path: "/v4", RawBody: "!!bukan-base64!!"}
	payload, _ := json.Marshal(cr)

	resp, got := post(t, ts, "/authz", nil, payload)
	if resp.StatusCode != http.StatusInternalServerError || got.Decision != "deny" {
		t.Fatalf("status=%d decision=%s want 500/deny fail-closed", resp.StatusCode, got.Decision)
	}
}

// TestFailClosedOnShortSecretConfig: konfigurasi secret rusak → semua request
// berakhir deny (verifier go-sdk mengembalikan 500).
func TestFailClosedOnShortSecretConfig(t *testing.T) {
	cfg := testConfig(func(c *Config) { c.solo = sp.LoadedKeys{HMACSecret: "terlalu-pendek"} })
	ts := newTestServer(t, cfg)
	headers, body := signHMAC(t, "http://upstream.test/v4", "POST", map[string]interface{}{"hello": "world"})

	resp, got := post(t, ts, "/v4", headers, []byte(body))
	if resp.StatusCode != http.StatusInternalServerError || got.Decision != "deny" {
		t.Fatalf("status=%d decision=%s want 500/deny fail-closed", resp.StatusCode, got.Decision)
	}
}

// TestAEADBothModeRoundTrip: mode both (AEAD + HMAC), termasuk jalur raw_body
// base64 pada CheckRequest.
func TestAEADBothModeRoundTrip(t *testing.T) {
	aeadB64 := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	cfg := testConfig(func(c *Config) {
		c.Mode = sp.ModeBoth
		c.solo = sp.LoadedKeys{HMACSecret: testSecret, AEADKeyB64: aeadB64}
	})
	ts := newTestServer(t, cfg)

	client := sp.New(sp.Options{
		Mode:          sp.ModeBoth,
		Version:       sp.DefaultVersion,
		ClientID:      "c1",
		KeyID:         "k1",
		HMACSecretRaw: testSecret,
		AEADKeyB64:    aeadB64,
	})
	headers, body, err := client.BuildHeadersAndBody("http://upstream.test/v4", "POST", map[string]interface{}{"enc": true}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Jalur raw-mirror.
	resp, got := post(t, ts, "/v4", headers, []byte(body))
	if resp.StatusCode != http.StatusOK || got.Decision != "allow" || !strings.EqualFold(got.Mode, "BOTH") {
		t.Fatalf("raw-mirror: status=%d decision=%s mode=%s error=%s", resp.StatusCode, got.Decision, got.Mode, got.Error)
	}

	// Jalur check-json dengan raw_body (base64). Request ditandatangani ulang
	// agar nonce berbeda dan tidak tertangkap replay guard.
	headers2, body2, err := client.BuildHeadersAndBody("http://upstream.test/v4", "POST", map[string]interface{}{"enc": true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cr := checkRequest{}
	cr.Attributes.Request.HTTP = httpAttrs{
		Headers: headers2, Method: "POST", Path: "/v4",
		RawBody: base64.StdEncoding.EncodeToString([]byte(body2)),
	}
	payload, _ := json.Marshal(cr)
	resp2, got2 := post(t, ts, "/authz", nil, payload)
	if resp2.StatusCode != http.StatusOK || got2.Decision != "allow" {
		t.Fatalf("check-json/raw_body: status=%d decision=%s error=%s", resp2.StatusCode, got2.Decision, got2.Error)
	}
}

// TestOversizedBodyDenied: body melebihi batas → 413 deny.
func TestOversizedBodyDenied(t *testing.T) {
	cfg := testConfig(func(c *Config) { c.MaxBodyBytes = 64 })
	ts := newTestServer(t, cfg)
	headers, body := signHMAC(t, "http://upstream.test/v4", "POST", map[string]interface{}{"pad": strings.Repeat("x", 512)})

	resp, got := post(t, ts, "/v4", headers, []byte(body))
	if resp.StatusCode != http.StatusRequestEntityTooLarge || got.Decision != "deny" {
		t.Fatalf("status=%d decision=%s want 413/deny", resp.StatusCode, got.Decision)
	}
}

// TestEd25519SignAlg: verifikasi Ed25519 end-to-end (server config menentukan alg).
func TestEd25519SignAlg(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	privB64 := base64.StdEncoding.EncodeToString(priv)

	cfg := testConfig(func(c *Config) {
		c.SignAlg = sp.SignAlgEd25519
		c.solo = sp.LoadedKeys{HMACSecret: testSecret, Ed25519PublicKeyB64: pubB64}
	})
	ts := newTestServer(t, cfg)

	client := sp.New(sp.Options{
		Mode:                sp.ModeHMAC,
		SignAlg:             sp.SignAlgEd25519,
		Version:             sp.DefaultVersion,
		ClientID:            "c1",
		KeyID:               "k1",
		HMACSecretRaw:       testSecret,
		Ed25519SecretKeyB64: privB64,
	})
	headers, body, err := client.BuildHeadersAndBody("http://upstream.test/v4", "POST", map[string]interface{}{"alg": "ed25519"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, got := post(t, ts, "/v4", headers, []byte(body))
	if resp.StatusCode != http.StatusOK || got.Decision != "allow" {
		t.Fatalf("allow path: status=%d decision=%s error=%s", resp.StatusCode, got.Decision, got.Error)
	}

	headers["X-Signature"] = strings.Repeat("Z", len(headers["X-Signature"]))
	resp2, got2 := post(t, ts, "/v4", headers, []byte(body))
	// Signature rusak dapat ditolak sebagai format (400) maupun verifikasi
	// (401) — keduanya deny dan aman.
	if got2.Decision != "deny" || (resp2.StatusCode != http.StatusBadRequest && resp2.StatusCode != http.StatusUnauthorized) {
		t.Fatalf("tamper path: status=%d decision=%s want 4xx/deny", resp2.StatusCode, got2.Decision)
	}
}

// TestMethodMismatchInCheckRequest: atribut method pada CheckRequest yang tidak
// cocok dengan tanda tangan harus ditolak.
func TestMethodMismatchInCheckRequest(t *testing.T) {
	ts := newTestServer(t, testConfig(nil))
	headers, body := signHMAC(t, "http://upstream.test/v4", "GET", nil)

	resp, got := post(t, ts, "/authz", nil, checkRequestBody(t, headers, "DELETE", "/v4", body))
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d decision=%s want 4xx/deny", resp.StatusCode, got.Decision)
	}
	if got.Decision != "deny" {
		t.Fatalf("decision=%s want deny", got.Decision)
	}
}

// TestPathPrefixStripping: prefix ala Envoy path_prefix dilepas sebelum verifikasi.
func TestPathPrefixStripping(t *testing.T) {
	cfg := testConfig(func(c *Config) { c.PathPrefix = "/authz" })
	ts := newTestServer(t, cfg)
	headers, body := signHMAC(t, "http://upstream.test/v4?a=1", "POST", map[string]interface{}{"p": 1})

	resp, got := post(t, ts, "/authz/v4?a=1", headers, []byte(body))
	if resp.StatusCode != http.StatusOK || got.Decision != "allow" {
		t.Fatalf("status=%d decision=%s error=%s", resp.StatusCode, got.Decision, got.Error)
	}
}

// TestSplitPathQuery: unit test pemisah path/query.
func TestSplitPathQuery(t *testing.T) {
	cases := []struct{ in, path, query string }{
		{"/v4", "/v4", ""},
		{"/v4?a=1", "/v4", "a=1"},
		{"?a=1", "/", "a=1"},
		{"", "/", ""},
	}
	for _, c := range cases {
		p, q := splitPathQuery(c.in)
		if p != c.path || q != c.query {
			t.Errorf("splitPathQuery(%q)=(%q,%q) want (%q,%q)", c.in, p, q, c.path, c.query)
		}
	}
}

// TestMapDenyStatus: pemetaan status verifier → status HTTP respons.
func TestMapDenyStatus(t *testing.T) {
	cases := []struct{ in, want int }{
		{sp.StatusBadRequest, 400},
		{sp.StatusUnauthorized, 401},
		{sp.StatusUnprocessable, 422},
		{sp.StatusServerError, 500},
		{-1, 403},
	}
	for _, c := range cases {
		if got := mapDenyStatus(c.in); got != c.want {
			t.Errorf("mapDenyStatus(%d)=%d want %d", c.in, got, c.want)
		}
	}
}

// TestLoadConfigValidation: konfigurasi env tidak valid gagal cepat saat startup.
func TestLoadConfigValidation(t *testing.T) {
	getenv := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}

	if _, err := loadConfig(getenv(map[string]string{})); err == nil {
		t.Error("tanpa SP_SECRET/SP_KEYS_JSON harus error")
	}
	if _, err := loadConfig(getenv(map[string]string{"SP_SECRET": testSecret, "SP_KEYS_JSON": "{}"})); err == nil {
		t.Error("SP_SECRET dan SP_KEYS_JSON bersamaan harus error")
	}
	if _, err := loadConfig(getenv(map[string]string{"SP_SECRET": testSecret, "SP_MODE": "aneh"})); err == nil {
		t.Error("SP_MODE tak dikenal harus error")
	}
	if _, err := loadConfig(getenv(map[string]string{"SP_SECRET": "pendek"})); err == nil {
		t.Error("secret < 32 karakter harus error saat startup")
	}
	if _, err := loadConfig(getenv(map[string]string{"SP_SECRET": testSecret, "SP_REPLAY_REDIS": "redis://x"})); err == nil {
		t.Error("SP_REPLAY_REDIS (belum didukung) harus menolak start")
	}
	// Mode default (both) menuntut kunci AEAD tersedia — tanpa itu harus error.
	if _, err := loadConfig(getenv(map[string]string{"SP_SECRET": testSecret})); err == nil {
		t.Error("mode both tanpa SP_AEAD_KEY_B64 harus error saat startup")
	}
	ok, err := loadConfig(getenv(map[string]string{"SP_SECRET": testSecret, "SP_MODE": "hmac"}))
	if err != nil || ok.Mode != sp.ModeHMAC || !ok.single {
		t.Errorf("konfigurasi minimal hmac harus valid; err=%v", err)
	}
	aeadB64 := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	okBoth, err := loadConfig(getenv(map[string]string{
		"SP_SECRET": testSecret, "SP_AEAD_KEY_B64": aeadB64,
	}))
	if err != nil || okBoth.Mode != sp.ModeBoth {
		t.Errorf("mode both dengan kunci lengkap harus valid; err=%v", err)
	}
}

// TestReplayStoreClaim: perilaku klaim pertama vs replay.
func TestReplayStoreClaim(t *testing.T) {
	s := newMemoryReplayStore(10)
	if !s.Claim("a", 60) {
		t.Fatal("klaim pertama harus berhasil")
	}
	if s.Claim("a", 60) {
		t.Fatal("klaim kedua dalam TTL harus ditolak")
	}
	s.mu.Lock()
	s.m["a"] = time.Now().Add(-time.Second) // paksa kedaluwarsa
	s.mu.Unlock()
	if !s.Claim("a", 60) {
		t.Fatal("klaim setelah kedaluwarsa harus berhasil")
	}
}
