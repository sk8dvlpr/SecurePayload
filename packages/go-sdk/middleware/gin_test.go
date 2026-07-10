package middleware_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sk8dvlpr/securepayload-go/middleware"
	"github.com/sk8dvlpr/securepayload-go/securepayload"
)

const hmacSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestGinVerifySuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)

	client := securepayload.New(securepayload.Options{
		Mode:          securepayload.ModeHMAC,
		Version:       "3",
		ClientID:      "c1",
		KeyID:         "k1",
		HMACSecretRaw: hmacSecret,
		Clock:         func() int64 { return 1_700_000_000 },
		NonceGen:      func() string { return "bm9uY2UxMjM0NTY3ODkw" }, // base64("nonce1234567890")
	})
	server := securepayload.New(securepayload.Options{
		Mode:          securepayload.ModeHMAC,
		Version:       "3",
		HMACSecretRaw: hmacSecret,
		Clock:         func() int64 { return 1_700_000_000 },
		ReplayStore:   func(string, int) bool { return true },
	})

	headers, body, err := client.BuildHeadersAndBody("https://api.test/hook", "POST", map[string]interface{}{"ok": true}, nil)
	if err != nil {
		t.Fatalf("BuildHeadersAndBody: %v", err)
	}

	r := gin.New()
	r.POST("/hook", middleware.GinVerify(server), func(c *gin.Context) {
		res, ok := middleware.GinVerifyResult(c)
		if !ok || !res.OK {
			t.Errorf("expected verify result in context")
		}
		c.JSON(200, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodPost, "/hook", bytes.NewBufferString(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if resp["ok"] != true {
		t.Fatalf("unexpected response: %v", resp)
	}
}

func TestGinVerifyRejectsUnsigned(t *testing.T) {
	gin.SetMode(gin.TestMode)

	server := securepayload.New(securepayload.Options{
		Mode:          securepayload.ModeHMAC,
		Version:       "3",
		HMACSecretRaw: hmacSecret,
		Clock:         func() int64 { return 1_700_000_000 },
		ReplayStore:   func(string, int) bool { return true },
	})

	r := gin.New()
	r.POST("/hook", middleware.GinVerify(server), func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodPost, "/hook", bytes.NewBufferString(`{}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code < 400 {
		t.Fatalf("expected error status, got %d", w.Code)
	}
}
