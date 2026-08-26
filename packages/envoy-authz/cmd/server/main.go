// Package main mengimplementasikan Envoy ext_authz (HTTP check) service
// yang mendelegasikan seluruh verifikasi kriptografi ke packages/go-sdk.
//
// Konfigurasi dibaca dari environment variable (lihat README.md).
// Prinsip utama: fail-closed — semua jalur ambigu berakhir pada DENY,
// dan secret tidak pernah ditulis ke log maupun respons.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	sp "github.com/sk8dvlpr/securepayload-go/securepayload"
)

// keyEntry adalah satu entri pada SP_KEYS_JSON (mode multi-klien).
type keyEntry struct {
	Secret              string `json:"secret"`
	AEADKeyB64          string `json:"aead_key_b64"`
	Ed25519PublicKeyB64 string `json:"ed25519_public_key_b64"`
}

// Config menyimpan seluruh konfigurasi runtime service ext_authz.
type Config struct {
	ListenAddr   string
	Mode         sp.Mode
	SignAlg      sp.SignAlg
	Version      string
	DeriveKeys   bool
	BindHeaders  []string
	ReplayTTL    int
	ClockSkew    int
	MaxBodyBytes int64
	PathPrefix   string // prefix yang dilepas dari path pada mode raw (mirror Envoy path_prefix)
	Clock        func() int64

	keys   map[string]sp.LoadedKeys // kunci "clientId|keyId"; nil pada mode single-secret
	solo   sp.LoadedKeys            // kunci tunggal; terisi hanya saat single=true
	single bool                     // true jika memakai SP_SECRET tunggal
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		log.Fatalf("config tidak valid: %v", err)
	}
	logConfigSummary(cfg)

	replay := newMemoryReplayStore(1_000_000)
	srv := newServer(cfg, replay)
	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go replay.janitor(ctx, 30*time.Second)

	errCh := make(chan error, 1)
	go func() {
		log.Printf("ext_authz listening on %s", cfg.ListenAddr)
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			log.Printf("shutdown: %v", err)
		}
		log.Println("ext_authz dihentikan dengan bersih")
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}
}

// loadConfig membangun Config dari env getter (di-inject agar mudah dites).
func loadConfig(getenv func(string) string) (*Config, error) {
	cfg := &Config{
		ListenAddr:   envOr(getenv, "SP_LISTEN_ADDR", ":9000"),
		Version:      envOr(getenv, "SP_VERSION", sp.DefaultVersion),
		ClockSkew:    60,
		ReplayTTL:    120,
		Clock:        func() int64 { return time.Now().Unix() },
		MaxBodyBytes: 1 << 20,
	}

	mode := strings.ToLower(envOr(getenv, "SP_MODE", string(sp.ModeBoth)))
	switch mode {
	case string(sp.ModeHMAC):
		cfg.Mode = sp.ModeHMAC
	case string(sp.ModeAEAD):
		cfg.Mode = sp.ModeAEAD
	case string(sp.ModeBoth):
		cfg.Mode = sp.ModeBoth
	default:
		return nil, fmt.Errorf("SP_MODE harus hmac|aead|both, dapat %q", mode)
	}

	signAlg := strings.ToLower(envOr(getenv, "SP_SIGN_ALG", string(sp.SignAlgHMAC)))
	switch signAlg {
	case string(sp.SignAlgHMAC):
		cfg.SignAlg = sp.SignAlgHMAC
	case string(sp.SignAlgEd25519):
		cfg.SignAlg = sp.SignAlgEd25519
	default:
		return nil, fmt.Errorf("SP_SIGN_ALG harus hmac|ed25519, dapat %q", signAlg)
	}

	var err error
	if cfg.ReplayTTL, err = envIntOr(getenv, "SP_REPLAY_TTL", 120); err != nil {
		return nil, err
	}
	if cfg.ClockSkew, err = envIntOr(getenv, "SP_CLOCK_SKEW", 60); err != nil {
		return nil, err
	}
	var maxBody int
	if maxBody, err = envIntOr(getenv, "SP_MAX_BODY_BYTES", 1<<20); err != nil {
		return nil, err
	}
	cfg.MaxBodyBytes = int64(maxBody)
	if cfg.DeriveKeys, err = envBoolOr(getenv, "SP_DERIVE_KEYS", false); err != nil {
		return nil, err
	}
	cfg.PathPrefix = envOr(getenv, "SP_PATH_PREFIX", "")

	for _, h := range strings.Split(envOr(getenv, "SP_BIND_HEADERS", ""), ",") {
		if h = strings.TrimSpace(h); h != "" {
			cfg.BindHeaders = append(cfg.BindHeaders, h)
		}
	}

	if redisURL := getenv("SP_REPLAY_REDIS"); strings.TrimSpace(redisURL) != "" {
		return nil, errors.New("SP_REPLAY_REDIS belum didukung pada rilis ini; " +
			"replay store saat ini in-process saja. Hapus variabel ini agar service mau start " +
			"(jangan biarkan service berjalan multi-replika tanpa replay store bersama)")
	}

	switch {
	case getenv("SP_KEYS_JSON") != "" && getenv("SP_SECRET") != "":
		return nil, errors.New("isi salah satu saja: SP_KEYS_JSON atau SP_SECRET")
	case getenv("SP_KEYS_JSON") != "":
		if err := cfg.loadKeysJSON(getenv("SP_KEYS_JSON")); err != nil {
			return nil, err
		}
	default:
		if err := cfg.loadSingleSecret(getenv); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// loadSingleSecret menyiapkan mode single-secret (SP_SECRET + teman-temannya).
func (c *Config) loadSingleSecret(getenv func(string) string) error {
	lk := sp.LoadedKeys{
		HMACSecret:          getenv("SP_SECRET"),
		AEADKeyB64:          getenv("SP_AEAD_KEY_B64"),
		Ed25519PublicKeyB64: getenv("SP_ED25519_PUBLIC_KEY_B64"),
	}
	if err := c.validateKeys(lk); err != nil {
		return fmt.Errorf("kunci tunggal tidak valid: %w", err)
	}
	c.solo = lk
	c.single = true
	return nil
}

// loadKeysJSON menyiapkan mode multi-klien. Format:
//
//	{"<clientId>|<keyId>": {"secret": "...", "aead_key_b64": "...", "ed25519_public_key_b64": "..."}}
func (c *Config) loadKeysJSON(raw string) error {
	var entries map[string]keyEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return fmt.Errorf("SP_KEYS_JSON bukan JSON yang valid: %w", err)
	}
	if len(entries) == 0 {
		return errors.New("SP_KEYS_JSON kosong")
	}
	c.keys = make(map[string]sp.LoadedKeys, len(entries))
	for id, e := range entries {
		parts := strings.SplitN(id, "|", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return fmt.Errorf("SP_KEYS_JSON: kunci registrasi harus berbentuk \"<clientId>|<keyId>\", dapat %q", redact(id))
		}
		lk := sp.LoadedKeys{
			HMACSecret:          e.Secret,
			AEADKeyB64:          e.AEADKeyB64,
			Ed25519PublicKeyB64: e.Ed25519PublicKeyB64,
		}
		if err := c.validateKeys(lk); err != nil {
			return fmt.Errorf("SP_KEYS_JSON[%s]: %w", redact(id), err)
		}
		c.keys[id] = lk
	}
	return nil
}

// validateKeys memastikan material kunci mencukupi untuk mode & algoritma terpilih.
// Dipanggil saat startup supaya kesalahan konfigurasi gagal cepat, bukan saat trafik datang.
func (c *Config) validateKeys(lk sp.LoadedKeys) error {
	if c.Mode == sp.ModeHMAC || c.Mode == sp.ModeBoth {
		if len(lk.HMACSecret) < 32 {
			return errors.New("secret HMAC minimal 32 karakter")
		}
	}
	if c.Mode == sp.ModeAEAD || c.Mode == sp.ModeBoth {
		raw, err := base64.StdEncoding.DecodeString(lk.AEADKeyB64)
		if err != nil || len(raw) != 32 {
			return errors.New("aead_key_b64 harus base64 dari tepat 32 byte")
		}
	}
	if c.SignAlg == sp.SignAlgEd25519 {
		raw, err := base64.StdEncoding.DecodeString(lk.Ed25519PublicKeyB64)
		if err != nil || len(raw) != 32 {
			return errors.New("ed25519_public_key_b64 harus base64 dari tepat 32 byte (public key)")
		}
	}
	return nil
}

// buildClient membuat verifier go-sdk sesuai konfigurasi.
// replay adalah replay store aktif (in-process); nil berarti tanpa proteksi
// replay — hanya diterima pada pengujian.
func (c *Config) buildClient(replay ReplayStore) *sp.Client {
	opts := sp.Options{
		Mode:        c.Mode,
		SignAlg:     c.SignAlg,
		Version:     c.Version,
		DeriveKeys:  c.DeriveKeys,
		BindHeaders: c.BindHeaders,
		ReplayTTL:   c.ReplayTTL,
		ClockSkew:   c.ClockSkew,
		Clock:       c.Clock,
	}
	if replay != nil {
		opts.ReplayStore = func(cacheKey string, ttl int) bool {
			return replay.Claim(cacheKey, ttl)
		}
	}
	if c.single {
		// Mode tunggal: satu set kunci untuk semua clientId/keyId (paritas dengan
		// perilaku default resolveKeys go-sdk). Identitas tetap diverifikasi
		// konsistensinya lewat tanda tangan.
		opts.KeyLoader = nil
		opts.HMACSecretRaw = c.solo.HMACSecret
		opts.AEADKeyB64 = c.solo.AEADKeyB64
		opts.Ed25519PublicKeyB64 = c.solo.Ed25519PublicKeyB64
	} else {
		keys := c.keys
		opts.KeyLoader = func(clientID, keyID string) sp.LoadedKeys {
			return keys[clientID+"|"+keyID]
		}
	}
	return sp.New(opts)
}

// logConfigSummary mencetak ringkasan konfigurasi TANPA material secret.
func logConfigSummary(c *Config) {
	keySource := "SP_SECRET (tunggal)"
	if !c.single {
		keySource = fmt.Sprintf("SP_KEYS_JSON (%d entri)", len(c.keys))
	}
	log.Printf("config: mode=%s sign_alg=%s version=%s derive_keys=%t bind_headers=%d replay_ttl=%ds clock_skew=%ds max_body=%dB path_prefix=%q keys=%s",
		c.Mode, c.SignAlg, c.Version, c.DeriveKeys, len(c.BindHeaders),
		c.ReplayTTL, c.ClockSkew, c.MaxBodyBytes, c.PathPrefix, keySource)
}

// redact menyamarkan identifier registrasi kunci untuk pesan error/log
// (identifier bukan secret, namun tetap tidak perlu terekspos penuh).
func redact(s string) string {
	i := strings.IndexByte(s, '|')
	if i < 0 {
		i = len(s)
	}
	if i > 3 {
		i = 3
	}
	return s[:i] + "***"
}

func envOr(getenv func(string) string, key, def string) string {
	if v := strings.TrimSpace(getenv(key)); v != "" {
		return v
	}
	return def
}

func envIntOr(getenv func(string) string, key string, def int) (int, error) {
	v := strings.TrimSpace(getenv(key))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s harus bilangan bulat, dapat %q", key, v)
	}
	return n, nil
}

func envBoolOr(getenv func(string) string, key string, def bool) (bool, error) {
	v := strings.ToLower(strings.TrimSpace(getenv(key)))
	if v == "" {
		return def, nil
	}
	switch v {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("%s harus boolean, dapat %q", key, v)
	}
}
