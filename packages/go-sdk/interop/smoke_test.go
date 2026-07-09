package interop_test

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sk8dvlpr/securepayload-go/securepayload"
	"github.com/sk8dvlpr/securepayload-go/testutil"
)

func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func phpScript(name string) string {
	return filepath.Join(repoRoot(), "packages", "node-sdk", "tests", "interop", name)
}

func loadKeys(t *testing.T) map[string]string {
	t.Helper()
	var keys map[string]string
	if err := testutil.LoadJSON(filepath.Join(testutil.FixturesRoot(), "keys", "standard.json"), &keys); err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestGoBuild_PHPVerify(t *testing.T) {
	if _, err := exec.LookPath("php"); err != nil {
		t.Skip("php not in PATH")
	}
	keys := loadKeys(t)
	client := securepayload.New(securepayload.Options{
		Mode:          securepayload.ModeBoth,
		SignAlg:       securepayload.SignAlgHMAC,
		Version:       "3",
		ClientID:      keys["clientId"],
		KeyID:         keys["keyId"],
		HMACSecretRaw: keys["hmacSecret"],
		AEADKeyB64:    keys["aeadKeyB64"],
		Clock:         func() int64 { return 1700000000 },
		NonceGen:      func() string { return "AQEBAQEBAQEBAQEBAQEBAQ==" },
	})

	headers, body, err := client.BuildHeadersAndBody(
		"https://example.test/v1/pay?a=1&b=2",
		"POST",
		map[string]interface{}{"amount": 100},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"headers": headers,
		"body":    body,
	})
	cmd := exec.Command("php", phpScript("php_verify.php"))
	cmd.Dir = filepath.Join(repoRoot(), "packages", "node-sdk")
	cmd.Stdin = bytes.NewReader(payload)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("php_verify.php failed: %v\n%s", err, out)
	}
	var result struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("invalid json from php: %s", out)
	}
	if !result.OK {
		t.Fatalf("PHP verify failed: %s", out)
	}
}

func TestPHPBuild_GoVerify(t *testing.T) {
	if _, err := exec.LookPath("php"); err != nil {
		t.Skip("php not in PATH")
	}
	cmd := exec.Command("php", phpScript("php_build.php"))
	cmd.Dir = filepath.Join(repoRoot(), "packages", "node-sdk")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("php_build.php failed: %v\n%s", err, out)
	}
	var req struct {
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	}
	if err := json.Unmarshal(out, &req); err != nil {
		t.Fatalf("invalid json from php: %s", out)
	}

	keys := loadKeys(t)
	server := securepayload.New(securepayload.Options{
		Mode:        securepayload.ModeBoth,
		SignAlg:     securepayload.SignAlgHMAC,
		Version:     "3",
		Clock:       func() int64 { return 1700000000 },
		ReplayStore: func(string, int) bool { return true },
		KeyLoader: func(string, string) securepayload.LoadedKeys {
			return securepayload.LoadedKeys{
				HMACSecret: keys["hmacSecret"],
				AEADKeyB64: keys["aeadKeyB64"],
			}
		},
	})
	result := server.Verify(req.Headers, req.Body, "POST", "/v1/pay", map[string]string{"a": "1", "b": "2"})
	if !result.OK {
		t.Fatalf("Go verify failed: %s (status %d)", result.Error, result.Status)
	}
}
