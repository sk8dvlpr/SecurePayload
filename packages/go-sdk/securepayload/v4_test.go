package securepayload_test

import (
	"testing"

	"github.com/sk8dvlpr/securepayload-go/securepayload"
)

func TestDefaultVersionIs4(t *testing.T) {
	if securepayload.DefaultVersion != "4" {
		t.Fatalf("DefaultVersion=%s want 4", securepayload.DefaultVersion)
	}
}

func TestV4JsonRoundTrip(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	client := securepayload.New(securepayload.Options{
		Mode:          securepayload.ModeHMAC,
		Version:       "4",
		ClientID:      "c1",
		KeyID:         "k1",
		HMACSecretRaw: secret,
		Clock:         func() int64 { return 1_700_000_000 },
		NonceGen:      func() string { return "bm9uY2UxMjM0NTY3ODkw" },
	})
	server := securepayload.New(securepayload.Options{
		Mode:          securepayload.ModeHMAC,
		Version:       "4",
		HMACSecretRaw: secret,
		Clock:         func() int64 { return 1_700_000_000 },
		ReplayStore:   func(string, int) bool { return true },
	})

	headers, body, err := client.BuildHeadersAndBody("https://api.test/v4", "POST", map[string]interface{}{"v": 4}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if headers["X-Signature-Version"] != "4" {
		t.Fatalf("version header=%s", headers["X-Signature-Version"])
	}
	res := server.Verify(headers, body, "POST", "/v4", "")
	if !res.OK {
		t.Fatalf("verify failed: %s", res.Error)
	}
}
