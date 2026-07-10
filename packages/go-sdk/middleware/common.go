package middleware

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/sk8dvlpr/securepayload-go/securepayload"
)

// ContextKey adalah tipe kunci konteks untuk hasil verifikasi SecurePayload.
type ContextKey string

// VerifyResultKey menyimpan *securepayload.VerifyResult di context request.
const VerifyResultKey ContextKey = "securepayload.verifyResult"

// NormalizeHeaders menormalisasi nama header ke UPPER-CASE (mirror PHP/Node).
func NormalizeHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		out[strings.ToUpper(k)] = v
	}
	return out
}

// HeadersFromHTTP mengubah http.Header menjadi map[string]string (nilai pertama per key).
func HeadersFromHTTP(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vals := range h {
		if len(vals) == 0 {
			continue
		}
		out[k] = vals[0]
	}
	return out
}

// WriteJSONError menulis respons error JSON dengan status HTTP.
func WriteJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// FailStatus memilih status HTTP dari hasil verifikasi.
func FailStatus(result securepayload.VerifyResult) int {
	if result.Status >= 400 {
		return result.Status
	}
	return http.StatusUnauthorized
}

// FailMessage memilih pesan error dari hasil verifikasi.
func FailMessage(result securepayload.VerifyResult) string {
	if result.Error != "" {
		return result.Error
	}
	return "unauthorized"
}
