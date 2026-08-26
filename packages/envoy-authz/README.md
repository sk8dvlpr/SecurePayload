# `envoy-authz` — Envoy External Authorization untuk SecurePayload

Service kecil berbasis Go yang membungkus verifier dari
[`packages/go-sdk`](../go-sdk) sebagai [Envoy ext_authz](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter)
(HTTP check) service. **Tidak ada kripto baru** — seluruh verifikasi tanda
tangan/digest/AEAD didelegasikan ke go-sdk yang sudah lulus conformance v3,
sehingga paritas kripto dengan aplikasi backend tercapai sejak hari pertama.

## Arsitektur

```
klien → Envoy :10000 → [ext_authz filter] → authz :9000 (service ini)
                      → [router]          → upstream aplikasi Anda
```

- Mode input ganda:
  - **check-json** — body CheckRequest JSON (`attributes.request.http.*`,
    mode gRPC / bridge JSON Envoy).
  - **raw-mirror** — mode `http_service` Envoy memirror request asli
    (header+method+path+body utuh); ekstraksi mengikuti pola middleware go-sdk.
  Deteksi otomatis; arah kesalahan deteksi selalu aman karena gerbang akhir
  adalah verifikasi tanda tangan atas `(method, path, query, body)` —
  ekstraksi salah tidak pernah menghasilkan ALLOW.
- **Fail-closed**: semua jalur ambigu → deny atau 5xx (Envoy memetakan 5xx
  menjadi tolak karena `failure_mode_allow: false`).

## Konfigurasi (environment variable)

| Variabel | Default | Keterangan |
|---|---|---|
| `SP_LISTEN_ADDR` | `:9000` | Alamat listen HTTP |
| `SP_SECRET` | — | Secret HMAC tunggal (min 32 karakter). Wajib salah satu: ini atau `SP_KEYS_JSON` |
| `SP_KEYS_JSON` | — | Multi-klien: `{"<clientId>\|<keyId>": {"secret":"...","aead_key_b64":"...","ed25519_public_key_b64":"..."}}` |
| `SP_AEAD_KEY_B64` | — | Kunci AEAD base64-32-byte (wajib utk mode aead/both) |
| `SP_ED25519_PUBLIC_KEY_B64` | — | Public key Ed25519 base64 (wajib bila `SP_SIGN_ALG=ed25519`) |
| `SP_MODE` | `hmac` | `hmac` \| `aead` \| `both` |
| `SP_SIGN_ALG` | `hmac` | `hmac` \| `ed25519` — anti-downgrade, ditentukan server |
| `SP_VERSION` | versi default go-sdk | Versi protokol |
| `SP_DERIVE_KEYS` | `false` | Aktifkan HKDF subkey (`sp-*-req\|v<ver>`) |
| `SP_BIND_HEADERS` | *(kosong)* | Daftar header terikat AAD, dipisah koma |
| `SP_CLOCK_SKEW` | `60` | Toleransi jam (detik) |
| `SP_REPLAY_TTL` | `120` | Umur entri anti-replay (detik) |
| `SP_MAX_BODY_BYTES` | `1048576` | Batas body check request |
| `SP_PATH_PREFIX` | *(kosong)* | Prefix yang dilepas dari path pada mode raw-mirror (mirror fitur `path_prefix` Envoy) |
| `SP_REPLAY_REDIS` | *(tidak didukung)* | Saat ini **ditolak saat startup** — replay store in-process saja. Jangan jalankan multi-replika tanpa replay store bersama |

Secret tidak pernah ditulis ke log maupun respons; log hanya memuat
keputusan/status/sumber/duration.

## Menjalankan demo lokal (manual)

Prasyarat: Docker + Docker Compose tersedia.

```bash
# 1) Secret demo (Linux/macOS):
export SP_SECRET="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
# PowerShell:
#   $env:SP_SECRET = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) })

# 2) Naikkan stack (context build = packages/, agar replace ../go-sdk ikut):
cd packages/envoy-authz/deploy
docker compose up --build

# 3) Dari terminal lain, buat request ter-tanda-tangan tanpa menulis kode klien:
cd packages/envoy-authz
export SP_SECRET="<nilai yang sama>"
go run ./cmd/sp-sign -url http://localhost:10000/v4 -method POST -data '{"hello":"world"}'
# → perintah curl siap tempel; jalankan → harus "hello from upstream" (allow)

# 4) Uji negatif (manual): ubah satu karakter header X-Signature pada curl → 401;
#    kirim ulang curl persis sama dua kali dalam TTL replay → yang kedua ditolak.
```

Tanpa Docker, service tetap bisa dicoba langsung:

```bash
go run ./cmd/server            # listen :9000
go run ./cmd/sp-sign -url http://127.0.0.1:9000/ -method POST -data '{"a":1}'
```

## Verifikasi (CI & lokal)

```bash
cd packages/envoy-authz
go build ./...   # kompilasi
go vet ./...     # static analysis
go test ./...    # unit test (httptest in-process — tidak listen port nyata)
```

Unit test mencakup: mapping request→verify→allow/deny, tamper signature → deny,
header hilang → deny, error internal → fail-closed, klasifikasi klien tak
terdaftar pada mode multi-kunci.

## Catatan produksi

1. **mTLS Envoy ↔ authz** — contoh compose berjalan plain di jaringan internal.
   Di produksi, pasang mTLS antara Envoy dan service authz (atau jalankan
   authz sebagai sidecar di host yang sama, bound ke localhost).
2. **Latency budget** — timeout ext_authz pada `deploy/envoy.yaml` sengaja 1s
   untuk demo; target produksi 100–250ms. Verifikasi HMAC sangat murah; biaya
   dominan adalah hop jaringan — gunakan sidecar/deployment berdekatan.
3. **Replay store bersama** — replay store saat ini in-process. Untuk
   multi-replika, integrasikan Redis (SET NX EX) sebelum scale-out horizontal;
   variabel `SP_REPLAY_REDIS` disiapkan sebagai guard agar tidak lupa.
4. **`failure_mode_allow: false`** wajib — authz down berarti semua request
   ditolak (fail-closed), bukan lolos tanpa verifikasi.
5. **Body besar** — `with_request_body.max_request_bytes` (8 KiB di sampel) +
   `allow_partial_message: false`: request lebih besar dari itu ditolak oleh
   filter, bukan diverifikasi tanpa body. Sesuaikan dengan profil payload Anda
   dan sinkronkan dengan `SP_MAX_BODY_BYTES`.
6. **Path signing** — pastikan route Envoy tidak menulis-ulang path yang
   ditandatangani klien (setara catatan `strip_path` pada plugin Kong).
