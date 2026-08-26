package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	sp "github.com/sk8dvlpr/securepayload-go/securepayload"
)

// Header keamanan protokol (stabil lintas v3/v4) — hanya dipakai untuk
// klasifikasi "klien tidak dikenal" sebelum verifikasi; keputusan akhir tetap
// miliki verifier kriptografi.
const (
	hdrClientID = "x-client-id"
	hdrKeyID    = "x-key-id"
)

// server adalah handler HTTP ext_authz. Fail-closed: setiap jalur ambigu
// menghasilkan deny (atau 5xx, yang oleh Envoy dipetakan menjadi deny karena
// failure_mode_allow=false).
type server struct {
	cfg    *Config
	client *sp.Client // verifier — seluruh kripto berasal dari go-sdk
	replay ReplayStore
	mux    *http.ServeMux
}

// newServer menyusun handler beserta rutenya.
func newServer(cfg *Config, replay ReplayStore) *server {
	s := &server{cfg: cfg, client: cfg.buildClient(replay), replay: replay}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	// Semua path lain diperlakukan sebagai check request, karena Envoy dapat
	// menambahkan path_prefix di depan target asli (fitur http_service).
	s.mux.HandleFunc("/", s.handleCheck)
	return s
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// handleHealthz menyediakan liveness probe tanpa membocorkan detail konfigurasi.
func (s *server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// httpAttrs adalah AttributeContext.HttpRequest (subset yang relevan).
type httpAttrs struct {
	Headers map[string]string `json:"headers"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Body    string            `json:"body"`
	RawBody string            `json:"raw_body"` // proto bytes → base64
}

// checkRequest adalah bentuk JSON service.auth.v3.CheckRequest (proto3 JSON)
// yang dikirim Envoy pada mode gRPC / bridge JSON.
type checkRequest struct {
	Attributes struct {
		Request struct {
			HTTP httpAttrs `json:"http"`
		} `json:"request"`
	} `json:"attributes"`
}

// extracted menampung data request asli siap verifikasi.
type extracted struct {
	headers map[string]string
	method  string
	path    string
	query   string
	body    string
	source  string // "check-json" | "raw-mirror"
}

// handleCheck memproses satu authorization check dan memutuskan allow/deny.
//
// Kontrak respons (mode http_service/raw Envoy — lihat ext_authz_http_impl.cc):
//   - HTTP 200          → allow
//   - HTTP 4xx lain     → deny, status & body dipass-through ke klien downstream
//   - HTTP 5xx          → error authz; Envoy menolak request (fail-closed, 403 default)
func (s *server) handleCheck(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status, payload, logErr := s.authorize(w, r)
	logDecision(status, payload["decision"], extractedSource(payload), start, logErr)
}

// authorize melakukan seluruh alur parsing → verifikasi → pemetaan keputusan.
func (s *server) authorize(w http.ResponseWriter, r *http.Request) (int, map[string]interface{}, error) {
	if r.Method != http.MethodPost {
		return s.deny(w, http.StatusMethodNotAllowed, "metode harus POST")
	}

	body, err := readBody(r, s.cfg.MaxBodyBytes)
	if err != nil {
		var tooLarge *maxBodyError
		if errors.As(err, &tooLarge) {
			return s.deny(w, http.StatusRequestEntityTooLarge, "body melebihi batas")
		}
		return s.deny(w, http.StatusBadRequest, "gagal membaca body")
	}

	ex, err := s.extract(r, body)
	if err != nil {
		// Input ambigu/rusak → fail-closed dengan 500 agar Envoy menolak request.
		return s.deny(w, http.StatusInternalServerError, "internal error")
	}

	if st, msg, skip := s.classifyUnknownClient(ex); skip {
		return s.deny(w, st, msg)
	}

	result := s.client.Verify(ex.headers, ex.body, ex.method, ex.path, ex.query)
	if result.OK {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"decision": "allow",
			"mode":     result.Mode,
		})
		return http.StatusOK, map[string]interface{}{"decision": "allow", "source": ex.source}, nil
	}

	st := mapDenyStatus(result.Status)
	writeJSON(w, st, map[string]interface{}{
		"decision": "deny",
		"status":   st,
		"error":    result.Error,
	})
	return st, map[string]interface{}{"decision": "deny", "source": ex.source}, nil
}

// extract mengambil (headers, method, path, query, body) request ASLI dari salah
// satu bentuk input yang didukung:
//
//  1. check-json : body berupa CheckRequest JSON (mode gRPC/bridge JSON Envoy,
//     bentuk sesuai service/ext_authz/v3 + attribute_context.proto v3:
//     attributes.request.http.{headers(map), method, path(termasuk query),
//     body | raw_body(base64)}).
//  2. raw-mirror : mode http_service ("RawHttp") Envoy TIDAK mengirim JSON;
//     ia memirror request asli (header+method+path+body utuh). Ekstraksi
//     mengikuti pola middleware go-sdk: URL.Path, URL.RawQuery, header nilai
//     pertama, body mentah.
//
// Deteksi: JSON valid yang memiliki attributes.request.http non-kosong dianggap
// check-json; selain itu raw-mirror. Arah kesalahan deteksi selalu aman karena
// gerbang terakhir adalah tanda tangan atas (method,path,query,body,digest) —
// ekstraksi yang salah tidak akan pernah menghasilkan ALLOW.
func (s *server) extract(r *http.Request, body []byte) (*extracted, error) {
	if len(body) > 0 && body[0] == '{' {
		var cr checkRequest
		if err := json.Unmarshal(body, &cr); err == nil {
			httpReq := cr.Attributes.Request.HTTP
			if httpReq.Method != "" || httpReq.Path != "" || len(httpReq.Headers) > 0 {
				return fromCheckRequest(&httpReq)
			}
		}
	}
	return s.fromRawMirror(r, body), nil
}

// fromCheckRequest mengonversi atribut CheckRequest menjadi input verifier.
func fromCheckRequest(h *httpAttrs) (*extracted, error) {
	payload := h.Body
	if h.RawBody != "" {
		raw, err := base64.StdEncoding.DecodeString(h.RawBody)
		if err != nil {
			return nil, errors.New("raw_body bukan base64 yang valid")
		}
		payload = string(raw)
	}
	path, query := splitPathQuery(h.Path)
	return &extracted{
		headers: h.Headers,
		method:  strings.ToUpper(h.Method),
		path:    path,
		query:   query,
		body:    payload,
		source:  "check-json",
	}, nil
}

// fromRawMirror mengekstrak request asli dari HTTP check request itu sendiri.
func (s *server) fromRawMirror(r *http.Request, body []byte) *extracted {
	path := r.URL.Path
	if s.cfg.PathPrefix != "" {
		path = strings.TrimPrefix(path, s.cfg.PathPrefix)
	}
	if path == "" {
		path = "/"
	}
	headers := make(map[string]string, len(r.Header))
	for k, vals := range r.Header {
		if len(vals) > 0 {
			headers[k] = vals[0]
		}
	}
	return &extracted{
		headers: headers,
		method:  r.Method,
		path:    path,
		query:   r.URL.RawQuery,
		body:    string(body),
		source:  "raw-mirror",
	}
}

// classifyUnknownClient menolak lebih awal pasangan clientId/keyId yang tidak
// terdaftar pada mode multi-kunci (SP_KEYS_JSON), sehingga klien tak dikenal
// menerima 401 (bukan 500 dari resolver kunci go-sdk). Pada mode single-secret
// pasangan mana pun diterima untuk diverifikasi (paritas perilaku default SDK).
func (s *server) classifyUnknownClient(ex *extracted) (int, string, bool) {
	if s.cfg.single || s.cfg.keys == nil {
		return 0, "", false
	}
	norm := make(map[string]string, len(ex.headers))
	for k, v := range ex.headers {
		norm[strings.ToUpper(k)] = v
	}
	cid, kid := norm["X-CLIENT-ID"], norm["X-KEY-ID"]
	if cid == "" || kid == "" {
		return 0, "", false // biarkan verifier yang menolak dengan pesan protokolnya
	}
	if _, ok := s.cfg.keys[cid+"|"+kid]; !ok {
		return http.StatusUnauthorized, "klien atau kunci tidak terdaftar", true
	}
	return 0, "", false
}

// mapDenyStatus memetakan status kegagalan verifier ke status HTTP respons.
// Status di luar rentang wajar dialihkan ke 403 (default deny Envoy).
func mapDenyStatus(st int) int {
	switch {
	case st == sp.StatusServerError:
		return http.StatusInternalServerError
	case st >= 400 && st <= 499:
		return st
	default:
		return http.StatusForbidden
	}
}

// deny menulis respons penolakan dan mengembalikan data untuk logging.
func (s *server) deny(w http.ResponseWriter, status int, msg string) (int, map[string]interface{}, error) {
	writeJSON(w, status, map[string]interface{}{
		"decision": "deny",
		"status":   status,
		"error":    msg,
	})
	return status, map[string]interface{}{"decision": "deny", "source": "local"}, errors.New(msg)
}

// readBody membaca seluruh body dengan batas ketat.
func readBody(r *http.Request, limit int64) ([]byte, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, limit)
	buf, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, &maxBodyError{}
		}
		return nil, err
	}
	return buf, nil
}

type maxBodyError struct{}

func (*maxBodyError) Error() string { return "body terlalu besar" }

// splitPathQuery memisahkan path dan query. AttributeContext.HttpRequest.path
// memuat target lengkap termasuk query-string (dokumen proto: field query
// selalu kosong).
func splitPathQuery(full string) (string, string) {
	if i := strings.IndexByte(full, '?'); i >= 0 {
		p := full[:i]
		if p == "" {
			p = "/"
		}
		return p, full[i+1:]
	}
	if full == "" {
		return "/", ""
	}
	return full, ""
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// logDecision mencatat keputusan TANPA nilai header, body, query, maupun secret.
func logDecision(status int, decision, source interface{}, start time.Time, err error) {
	d := stringOr(decision, "?")
	src := stringOr(source, "?")
	if err != nil && status >= 500 {
		log.Printf("authz decision=%s status=%d source=%s duration_ms=%d internal_error=%v",
			d, status, src, time.Since(start).Milliseconds(), err)
		return
	}
	log.Printf("authz decision=%s status=%d source=%s duration_ms=%d", d, status, src, time.Since(start).Milliseconds())
}

func stringOr(v interface{}, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

// extractedSource mengambil sumber input dari payload log.
func extractedSource(payload map[string]interface{}) interface{} {
	return payload["source"]
}
