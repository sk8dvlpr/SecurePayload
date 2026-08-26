// Command sp-sign membuat perintah curl dengan header SecurePayload yang valid,
// untuk mencoba demo envoy-authz tanpa menulis kode klien.
//
// Contoh:
//
//	export SP_SECRET="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
//	go run ./cmd/sp-sign -url http://localhost:10000/v4 -method POST -data '{"hello":"world"}'
//
// Secret dibaca dari environment dan tidak pernah dicetak ke stdout.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	sp "github.com/sk8dvlpr/securepayload-go/securepayload"
)

func main() {
	log.SetFlags(0)
	url := flag.String("url", "http://localhost:10000/v4", "URL target (via Envoy)")
	method := flag.String("method", "POST", "HTTP method")
	data := flag.String("data", "{}", "payload JSON")
	flag.Parse()

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(*data), &payload); err != nil {
		log.Fatalf("payload -data bukan JSON objek yang valid: %v", err)
	}

	// Default hmac: selaras dengan demo docker-compose (tanpa kunci AEAD).
	mode := sp.Mode(strings.ToLower(envOr("SP_MODE", string(sp.ModeHMAC))))
	client := sp.New(sp.Options{
		Mode:          mode,
		Version:       envOr("SP_VERSION", sp.DefaultVersion),
		ClientID:      envOr("SP_CLIENT_ID", "demo-client"),
		KeyID:         envOr("SP_KEY_ID", "demo-key"),
		HMACSecretRaw: os.Getenv("SP_SECRET"),
		AEADKeyB64:    os.Getenv("SP_AEAD_KEY_B64"),
	})

	headers, body, err := client.BuildHeadersAndBody(*url, *method, payload, nil)
	if err != nil {
		log.Fatalf("gagal membangun request: %v", err)
	}

	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("curl -sv -X " + strings.ToUpper(*method) + " '" + shellQuote(*url) + "' ")
	for _, k := range keys {
		fmt.Fprintf(&b, "-H '%s: %s' ", k, shellQuote(headers[k]))
	}
	fmt.Fprintf(&b, "--data-binary '%s'", shellQuote(body))
	fmt.Println(b.String())
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// shellQuote melakukan escaping nilai untuk pembungkus single-quote shell.
func shellQuote(s string) string {
	return strings.ReplaceAll(s, "'", `'\''`)
}
