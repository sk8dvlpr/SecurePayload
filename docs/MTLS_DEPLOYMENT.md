# SecurePayload + mTLS — Panduan Deployment

Dokumen ini menjelaskan cara menggabungkan **mutual TLS (mTLS)** di lapisan transport dengan **SecurePayload** di lapisan aplikasi. Keduanya orthogonal: mTLS memverifikasi identitas koneksi TLS; SecurePayload memverifikasi integritas, autentikasi, dan (opsional) kerahasiaan payload HTTP.

**Wire protocol v3 tidak berubah** — panduan ini hanya arsitektur deployment.

---

## 1. Layering

| Lapisan | Fungsi | Contoh |
|---------|--------|--------|
| Transport (mTLS) | Client & server saling mempresentasikan sertifikat X.509 | Nginx `ssl_verify_client`, service mesh |
| Aplikasi (SecurePayload) | HMAC/Ed25519 + AEAD, anti-replay, binding AAD | `SecurePayload::verify()` / `WebhookVerifier` |

mTLS **tidak menggantikan** tanda tangan SecurePayload. Sebaliknya, SecurePayload **tidak** memverifikasi sertifikat TLS — itu tanggung jawab stack transport.

---

## 2. Terminasi mTLS: Proxy vs Aplikasi

### Reverse proxy (disarankan)

- Nginx/Envoy/HAProxy memverifikasi client certificate sebelum request mencapai PHP/Node.
- Aplikasi tetap memanggil `verify()` / `verifyFromGlobals()` pada **raw body** dan header `X-*`.
- Keuntungan: sertifikat dan CRL/OCSP dikelola terpusat di proxy.

### App-level mTLS

- PHP/Node memakai stream TLS dengan `verify_peer` + client cert — cocok untuk layanan kecil tanpa proxy.
- SecurePayload tetap dijalankan setelah HTTP request diterima utuh.

---

## 3. Header forwarding

Proxy **wajib** meneruskan header SecurePayload tanpa modifikasi:

- `X-Client-Id`, `X-Key-Id`, `X-Timestamp`, `X-Nonce`
- `X-Signature-*`, `X-Body-Digest`, `X-AEAD-*`
- Header `bindHeaders` (mis. `Content-Type`) jika dikonfigurasi

Contoh Nginx:

```nginx
proxy_set_header X-Client-Id $http_x_client_id;
proxy_set_header X-Signature $http_x_signature;
# ... atau proxy_pass_header untuk semua header custom
```

**Jangan** mengandalkan `X-Canonical-Request` untuk verifikasi — server harus memakai `method`/`path`/`query` dari request yang diterima (lihat `tests/Security/SignatureSpoofingTest.php`).

---

## 4. Path dan query di belakang proxy

SecurePayload menandatangani **path kanonik** dan **query string** yang dipakai server saat verifikasi.

| Skenario | Rekomendasi |
|----------|-------------|
| Proxy strip prefix (`/api` → `/`) | Konfigurasi rewrite konsisten; pass `path` yang sama dengan yang ditandatangani client |
| `X-Forwarded-*` | Jangan otomatis dipakai untuk signing tanpa kontrak eksplisit client–server |
| Webhook URL publik vs internal | Client harus sign URL yang **benar-benar** diterima verifier |

Gunakan [`WebhookVerifier`](../src/Webhook/WebhookVerifier.php) dengan `REQUEST_URI` yang sudah benar di PHP-FPM, atau middleware Express/Fastify di Node SDK dengan `req.path` / `request.url`.

---

## 5. Replay store di lingkungan multi-instance

mTLS tidak mencegah **replay** request yang sudah valid secara kriptografi. Di load balancer / multi-pod:

- Wajib injeksi `replayStore` bersama (Redis, Memcached).
- Adapter: [`Psr16ReplayStore`](../src/ReplayStore/Psr16ReplayStore.php).
- Contoh: [`examples/replay-store/redis.php`](../examples/replay-store/redis.php).

File-based replay cache bawaan **tidak** terbagi antar host.

---

## 6. Contoh Nginx + PHP-FPM

```nginx
server {
    listen 443 ssl;
    ssl_certificate     /etc/nginx/server.crt;
    ssl_certificate_key /etc/nginx/server.key;
    ssl_client_certificate /etc/nginx/ca.crt;
    ssl_verify_client on;

    location /webhook {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME /var/www/examples/webhook/verify.php;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
    }
}
```

PHP: [`examples/webhook/verify.php`](../examples/webhook/verify.php) memakai `WebhookVerifier::verifyFromGlobals()`.

---

## 7. Observability

- Metrik: [`PrometheusSecurityExporter`](../src/Observability/PrometheusSecurityExporter.php) + contoh [`examples/observability/prometheus.php`](../examples/observability/prometheus.php).
- Tracing: [`OpenTelemetrySecurityExporter`](../src/Observability/OpenTelemetrySecurityExporter.php) (opsional, `open-telemetry/sdk`).

Event keamanan tidak memuat secret atau plaintext.

---

## 8. Anti-patterns

1. **Hanya mTLS, tanpa SecurePayload** — partner bisa replay body jika tidak ada signing/nonce.
2. **Hanya SecurePayload, tanpa TLS** — traffic bisa di-sniff (gunakan HTTPS minimal).
3. **Membaca method/path dari header debug** — rentan spoofing signature context.
4. **Replay file-cache di cluster** — nonce bisa dipakai ulang di instance lain.
5. **Body ter-parse sebelum verify** — JSON re-encoding mengubah bytes; gunakan raw body (lihat README Node SDK middleware).

---

## Referensi

| Topik | Lokasi |
|-------|--------|
| Protokol v3 | [`docs/PROTOCOL.md`](PROTOCOL.md) |
| Webhook helper | [`src/Webhook/WebhookVerifier.php`](../src/Webhook/WebhookVerifier.php) |
| Node middleware | [`packages/node-sdk/README.md`](../packages/node-sdk/README.md) |
| Replay Redis | [`examples/replay-store/redis.php`](../examples/replay-store/redis.php) |
