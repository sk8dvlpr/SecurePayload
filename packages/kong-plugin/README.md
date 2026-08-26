# securepayload — Kong API Gateway Plugin (Lua/OpenResty) v1

Plugin verifikasi protokol **SecurePayload** di edge (Kong Gateway / OpenResty).
Port semantik dari `src/Protocol/{Canonical,Messages,Digest}.php` dan
`src/Server/RequestVerifier.php` (repo core). Murni Lua — satu-satunya
dependency native adalah **libcrypto OpenSSL via FFI** (SHA-256/HMAC), yang
sudah dibundel bersama Kong dan OpenResty.

## Batasan fundamental v1 (WAJIB dibaca)

Invarian protokol: **HMAC menandatangani plaintext**, dan
`X-Body-Digest = sha256(plaintext)` — sementara gateway hanya melihat body wire:

| Mode upstream | Perilaku gateway |
|---|---|
| `hmac` | **Verifikasi penuh**: keberadaan header, versi, window timestamp, format nonce, digest body plaintext, signature HMAC (constant-time), replay opsional (Redis). |
| `aead` / `both` | **MUSTAHIL diverifikasi penuh di gateway** (plaintext tersembunyi di balik AEAD). Hanya *structural checks*: header ada + format benar + timestamp dalam window + envelope `__aead_b64` ada. Request lanjut atau ditolak sesuai `unverified_mode_action`. |

Batasan lain yang menyertai v1 (lihat juga tabel [Limitasi](#limitasi-v1)):

- **Ed25519 & AEAD tidak dievaluasi di Lua** (defer — tidak native di OpenResty).
  `signAlg` non-HMAC dikonfigurasi hanya untuk *anti-downgrade check*;
  signature-nya sendiri tidak dapat diverifikasi gateway.
- Body di-buffer pada fase access untuk menghitung digest → ukuran dibatasi
  `client_max_body_size` Nginx/Kong.
- Bekerja juga untuk **Nginx/OpenResty polos** (modul murni, tanpa PDK wajib).

## Struktur

```
packages/kong-plugin/
├── kong/plugins/securepayload/
│   ├── schema.lua         # Schema plugin (field konfigurasi)
│   ├── handler.lua        # Adapter fase access (Kong PDK)
│   ├── verifier.lua       # Orkestrasi verifikasi (murni, port RequestVerifier)
│   ├── canonical.lua      # Port Canonical.php + Messages.php (+ parse_str PHP)
│   ├── crypto.lua         # SHA-256/HMAC via FFI EVP, ct_compare, base64, HKDF
│   └── replay_redis.lua   # Adapter lua-resty-redis (SET NX EX) — opsional
├── spec/handler_spec.lua  # Unit test busted standalone (tanpa Kong berjalan)
└── README.md
```

Semua logika verifikasi ada di modul murni (`verifier`, `canonical`, `crypto`);
`handler.lua` hanya pengumpul konteks request + responder error. Modul murni
inilah yang dipakai ulang oleh mode OpenResty polos dan busted.

## Instalasi

### Kong

1. Salin folder `kong/plugins/securepayload` ke node Kong (atau masukkan root
   repo ini ke `lua_package_path`):

   ```ini
   # kong.conf
   plugins = bundled,securepayload
   lua_package_path = /opt/securepayload/packages/kong-plugin/kong/?.lua;;
   ```

   (Jika memakai `lua_package_path`, pastikan path menunjuk ke direktori
   `kong/` hasil checkout repo.)

2. Restart/reload Kong, lalu aktifkan pada route/service.

### OpenResty polos

Tanpa schema/handler Kong — panggil modul murni langsung:

```nginx
# nginx.conf (OpenResty)
location /api/ {
    lua_need_request_body on;               -- atau read_body eksplisit di bawah
    set $sp_err "";
    access_by_lua_block {
        local verifier = require "kong.plugins.securepayload.verifier"
        ngx.req.read_body()
        local raw_body = ngx.req.get_body_data()
        if not raw_body then
            -- body besar tersimpan ke file temp; tolak atau naikkan
            -- client_max_body_size agar tetap di memori
            return ngx.exit(413)
        end
        local res = verifier.verify({
            version = "4", mode = "hmac",
            clock_skew = 5, replay_ttl = 300,
            hmac_secret = os.getenv("SP_HMAC_SECRET"),
        }, {
            headers  = ngx.req.get_headers(),
            method   = ngx.req.get_method(),
            path     = ngx.var.uri,          -- path apa adanya, sama seperti
                                             -- yang diteruskan ke upstream
            raw_query  = ngx.var.query_string or "",
            raw_body   = raw_body,
        })
        if not res.ok then
            ngx.status = res.status
            ngx.header.content_type = "application/json"
            ngx.say(string.format('{"error":%s}',
                require("cjson.safe").encode(res.error)))
            return ngx.exit(res.status)
        end
    }
    proxy_pass http://upstream;
}
```

> Catatan: gunakan `ngx.var.uri` (path apa adanya, sama seperti yang diteruskan
> ke upstream) supaya kanonisasi path identik dengan server PHP.

## Konfigurasi

| Field | Tipe | Default | Keterangan |
|---|---|---|---|
| `version` | string | `"4"` | Versi protokol (`X-Signature-Version`). Harus = config server PHP. |
| `mode` | `hmac\|aead\|both` | `"hmac"` | Mode upstream server. Menentukan verifikasi penuh vs structural. |
| `expected_sig_alg` | `HMAC-SHA256\|ED25519\|HYBRID-MLDSA44-ED25519` | `"HMAC-SHA256"` | Anti-downgrade: header `X-Signature-Algorithm` harus persis nilai ini (server-side decision, bukan client). Nilai selain HMAC → request ditolak 500 (plugin v1 tak bisa memverifikasinya). |
| `clock_skew` | integer ≥ 0 | `5` | Toleransi jam (detik). Window valid: `now-(replay_ttl+skew) ≤ ts ≤ now+skew`. |
| `replay_ttl` | integer ≥ 0 | `300` | TTL nonce (detik); TTL store efektif = `replay_ttl + clock_skew`. |
| `hmac_secret` | string ≥ 32 | – | Secret single-tenant. `referenceable` (bisa diisi vault reference). |
| `hmac_secrets` | map `"cid:kid"→secret` | `{}` | Multi-klien; lookup exact `clientId:keyId`, fallback ke `hmac_secret`. |
| `derive_keys` | boolean | `false` | Set `true` bila server PHP memakai opsi `deriveKeys => true` (subkey HKDF-SHA256 `sp-sign-req|v<ver>`). **Wajib sinkron** — mismatch = semua signature 401. |
| `replay_store` | record `{host,port}` | – | Redis untuk anti-replay (`SET NX EX`). Tanpa ini, cek replay dilewati. |
| `unverified_mode_action` | `pass\|reject` | `"pass"` | Untuk mode `aead`/`both` setelah structural checks lolos: `pass` = lanjut (log warn + metric), `reject` = 401. |

### Contoh: declarative (kong.yml)

```yaml
routes:
- name: payments
  paths: ["/v1/pay"]
  service: payments-svc
  plugins:
  - name: securepayload
    config:
      version: "4"
      mode: hmac
      clock_skew: 5
      replay_ttl: 300
      hmac_secret: "{vault://env/sp-hmac-secret}"
      replay_store:
        host: redis.internal
        port: 6379
      unverified_mode_action: pass
```

### Contoh: Admin API

```bash
curl -X POST http://localhost:8001/routes/payments/plugins \
  -H "Content-Type: application/json" \
  -d '{
    "name": "securepayload",
    "config": {
      "mode": "hmac",
      "clock_skew": 5,
      "replay_ttl": 300,
      "hmac_secrets": {
        "mobile-app:key-2026": "<secret-min-32-char>"
      },
      "replay_store": { "host": "127.0.0.1", "port": 6379 },
      "unverified_mode_action": "pass"
    }
  }'
```

Multi-klien: satu entri `"<clientId>:<keyId>"` per pasangan kunci; fallback
single-tenant lewat `config.hmac_secret`.

## Pemetaan status code (identik `SecurePayloadException`)

| Kondisi | HTTP |
|---|---|
| Header keamanan tidak lengkap / versi salah / format ts / format digest / algoritma salah / nonce invalid / envelope AEAD hilang | `400` |
| Timestamp di luar window / replay / signature invalid / AEAD alg tak dikenal saat mode wajib enkripsi / `unverified_mode_action=reject` | `401` |
| Integritas `X-Body-Digest` gagal | `422` |
| Secret tidak ditemukan / secret < 32 char / signAlg belum didukung / Redis down (fail-closed) / decoder JSON absen | `500` |

Body error JSON ringkas, kontrak sama dengan integrasi PHP:
`{"error": "<pesan>"}` + `Content-Type: application/json`.

## Smoke manual (Kong + upstream echo)

Siapkan upstream echo (service yang memakai SDK SecurePayload PHP/Node/Go),
route Kong dengan plugin di atas, lalu:

1. **Valid → pass**

   ```bash
   # 1) Bangun header + body bertanda tangan dengan SDK resmi (contoh Node):
   node -e '
     const {SecurePayload} = require("./packages/node-sdk/dist");
     const sp = new SecurePayload({version:"4", clientId:"cli", keyId:"key",
       hmacSecretB64: Buffer.from(process.env.SP_SECRET).toString("base64"),
       mode:"hmac"});
     const {headers, body} = sp.build("http://gw.local/v1/pay","POST",{amount:100});
     console.log(JSON.stringify({headers, body}));
   ' > /tmp/sp-req.json

   # 2) Kirim ke gateway (jq memetakan header JSON -> argumen curl):
   curl -sv http://localhost:8000/v1/pay \
     $(jq -r '.headers | to_entries[] | "-H", "\(.key): \(.value)"' /tmp/sp-req.json) \
     --data-binary "$(jq -r '.body' /tmp/sp-req.json)"
   ```
   Diharapkan: request diteruskan ke upstream (bukan 40x dari plugin).

2. **Tamper signature → 401** — ulangi dengan satu karakter `X-Signature`
   diubah. Diharapkan `401 {"error":"Tanda Tangan (Signature) tidak valid"}`.

3. **Replay nonce → 401 (Redis)** — kirim ulang request identik (nonce sama)
   dalam window TTL. Diharapkan `401 {"error":"Replay detected"}`. Pastikan
   `replay_store` terisi; tanpa Redis langkah ini dilewati plugin.

4. **Mode aead + `unverified_mode_action`**
   - `pass`: request AEAD valid → diteruskan, muncul log warn di error.log
     (`request terenkripsi dilewatkan TANPA verifikasi penuh`).
   - `reject`: request AEAD valid → `401`.
   - Body tanpa `__aead_b64` → `400 Payload AEAD tidak ditemukan`.

5. **Timestamp basi → 401** — ubah `X-Timestamp` ke `now - 400`.

## Limitasi v1

| Limitasi | Dampak | Mitigasi |
|---|---|---|
| Ed25519 / ML-DSA / AEAD tidak dievaluasi di Lua | Signature non-HMAC tak terverifikasi di gateway | Set `expected_sig_alg` agar request mismatch ditolak; verifikasi tetap penuh di upstream |
| `strip_path` route Kong mengubah path sebelum upstream | Path yang dikanonisisasi gateway ≠ path upstream → signature gagal | Gunakan routing tanpa `strip_path`, atau samakan path layanan |
| Body di-buffer di access phase | Memory pressure pada payload besar | Set `client_max_body_size` memadai; body > buffer memori Nginx tertolak 413 |
| Duplicate header `X-*` bernilai array | Dianggap header hilang → 400 fail-closed | Kirim tiap header sekali (SDK resmi demikian) |
| Query bracket-array (`a[]=1&a[]=2`) & nested `[` | Tidak didukung emulasi parse_str → bisa mismatch signature | Hindari di API bertanda tangan |
| `signAlg` ≠ HMAC-SHA256 | Semua request → 500 config error | Upgrade plugin (roadmap) atau matikan verifikasi di gateway |
| `derive_keys` harus sinkron dengan server | Mismatch = 401 massal | Dokumentasikan flag infrastruktur; uji smoke pertama |
| Metric belum first-class (log warn saja) | Alerting perlu parsing log / status code | Pasang Prometheus plugin untuk metrik status; event ada di log `securepayload event=...` |
| Nonce dipercayai base64-strict 16 byte | Client custom dengan nonce lain → 400 | Gunakan SDK resmi (`Digest::genNonceB64`) |
| Membutuhkan Kong ≥ 3.x (schema `referenceable`) | Validasi schema gagal di Kong lama | Hapus atribut `referenceable` jika terjebak versi lama |

## Keamanan

- Perbandingan signature & digest memakai **constant-time compare xor-fold**
  (`crypto.ct_compare`) — bukan `==`.
- Secret tidak pernah ditulis ke log/error; field secret `referenceable`
  sehingga bisa disimpan sebagai vault reference, bukan plaintext di Admin API.
- Fail-closed di semua jalur ambigu (Redis down → 500; decoder absen → 500;
  mode tak dikenal → 500).
- Anti-downgrade: `X-Signature-Algorithm` dicek terhadap konfigurasi
  (`expected_sig_alg`), bukan dipercaya dari client; mode wajib-enkripsi
  menolak request tanpa header AEAD yang sah.

## Testing (busted standalone)

```bash
cd packages/kong-plugin
busted          # butuh busted + LuaJIT/OpenResty; lihat .busted utk arg default
```

Cakupan: vektor `docs/fixtures/v3/primitive/{normalize-path,hmac-message,body-digest,hkdf-derive}.json`,
RFC 4648 base64, RFC 4231 HMAC, boundary window timestamp, constant-time
compare, semantik parse_str, jalur kegagalan verifier, structural checks AEAD.
Test yang butuh libcrypto otomatis *pending* bila FFI tidak dapat memuatnya.

> Catatan lingkungan dev Windows penulis: `busted`/LuaJIT tidak tersedia, maka
> eksekusi suite dilakukan via CI (Linux) atau manual di mesin dengan OpenResty.
