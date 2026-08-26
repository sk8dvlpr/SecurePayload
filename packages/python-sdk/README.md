# SecurePayload Python SDK (`packages/python-sdk`)

SDK Python untuk protokol **SecurePayload v3** — port byte-exact dari PHP core (`sk8dvlpr/securepayload`). Terverifikasi conformance terhadap fixture machine-readable `docs/fixtures/v3/` (primitif, wire, negative) plus smoke interop dua arah dengan PHP core.

> **Catatan versi**: SDK ini menargetkan protocol version `3`. Dukungan v4 (header set & hybrid PQ) menyusul di iterasi berikutnya — lihat `docs/ROADMAP.md`.

## Instalasi

```bash
pip install -e "packages/python-sdk"        # runtime (pynacl satu-satunya dependency)
pip install -e "packages/python-sdk[dev]"   # + pytest untuk menjalankan test
```

Syarat: Python ≥ 3.9. Kripto memakai [PyNaCl](https://pypi.org/project/pynacl/) (binding libsodium — primitif identik ext-sodium PHP).

## Quickstart — Client

```python
from securepayload import Options, SecurePayloadClient

client = SecurePayloadClient(Options(
    mode="both",                      # "hmac" | "aead" | "both"
    sign_alg="hmac",                  # atau "ed25519" (ditentukan config server; anti-downgrade)
    version="3",
    client_id="my-client",
    key_id="my-key",
    hmac_secret_raw="<64-char hex / >=32 char>",
    aead_key_b64="<base64 kunci 32 byte>",
    # Ed25519 (opsional): request ditandatangani keypair CLIENT
    # ed25519_secret_key_b64=...,      # base64 dari 64 byte (seed||pub)
))

headers, body = client.build_headers_and_body("https://api.example.com/v1/pay?a=1", "POST", {"amount": 100})
# kirim headers + body dengan HTTP client apa pun...
```

Memverifikasi response server (mode `hmac`/`both`, atau AEAD):

```python
result = client.verify_response(resp_headers, resp_body, req_nonce_b64=headers["X-Nonce"])
if result.ok:
    data = result.json          # payload hasil dekripsi/verifikasi
else:
    print(result.status, result.error)
```

## Quickstart — Server

```python
from securepayload import Options, SecurePayloadServer

server = SecurePayloadServer(Options(
    mode="both",
    sign_alg="hmac",                  # sumber kebenaran algoritma = config SERVER
    version="3",
    clock_skew=60,
    replay_ttl=120,
    key_loader=lambda client_id, key_id: {
        "hmac_secret": "...",         # per (clientId, keyId) dari DB/KMS Anda
        "aead_key_b64": "...",
        # verifikasi request ed25519: public key CLIENT
        "ed25519_public_key_b64": "...",
        # signing response ed25519: secret key SERVER (64 byte)
        "ed25519_secret_key_server_b64": "...",
    },
    # Produksi multi-proses WAJIB injeksi store persisten (Redis/Memcached):
    # replay_store=lambda cache_key, ttl: redis.setnx(cache_key, 1, ex=ttl),
))
```

Framework umumnya menyediakan header sebagai dict dan raw body sebagai string:

```python
result = server.verify(headers_dict, raw_body, method, path, query)   # query: dict | str
if not result.ok:
    return jsonify(error=result.error), result.status                 # 400/401/422/500

resp_headers, resp_body = server.build_response(headers_dict, {"status": "ok"})
```

## Jaminan keamanan yang dipertahankan (mirror PHP core)

- Server menurunkan `method`/`path`/`query` kanonik dari input request — **tidak pernah** dari header `X-Canonical-Request`.
- Kunci replay **tidak menyertakan timestamp**; TTL efektif = `replay_ttl + clock_skew`.
- Mode `both`: HMAC/digest dihitung atas **plaintext pra-enkripsi**.
- Semua perbandingan secret/signature/nonce constant-time (setara `hash_equals`).
- Anti-downgrade: mode `aead`/`both` menolak request/response tanpa AEAD valid; header `X-Signature-Algorithm` harus cocok `sign_alg` konfigurasi.
- Nonce AEAD diturunkan deterministik dari konteks request (anti nonce-reuse); AAD mengikat versi, timestamp, dan `bind_headers`.

## Menjalankan conformance

```bash
pytest packages/python-sdk/tests -q
```

| Suite | Isi |
|-------|-----|
| `test_primitive_v3.py` | semua `docs/fixtures/v3/primitive/*.json` → byte-exact (hex/b64) |
| `test_wire_v3.py` | semua `docs/fixtures/v3/wire/*.json` → rebuild `expected.headers` + `expected.body` persis, verify server, roundtrip response |
| `test_negative_v3.py` | semua `docs/fixtures/v3/negative/*.json` wajib `ok=false` |
| `test_interop_smoke.py` | subprocess PHP ↔ Python dua arah (skip bila PHP CLI/vendor tidak ada; CI menjalankannya penuh) |

## Catatan porting / deviasi sadar

1. **Query parsing**: `parse_qsl` menangani pasangan key=value sederhana; edge-case semantik `parse_str` PHP (titik/spasi→underscore pada nama key, sintaks `[]`) tidak direplikasi — pola sama dengan node-sdk. Query kanonisasi tetap identik via `canonical_query` (sort ASC + RFC 3986 `quote(safe='')` ≡ `rawurlencode`).
2. **Koersi nilai query**: mengikuti PHP (`true→'1'`, `false/null→''`), bukan `String()` JS. Float berformat berbeda dari PHP untuk nilai eksotis (mis. `1.0`) — tidak dipakai protokol.
3. **Replay store default**: in-process memory (paritas ReplayGuard PHP untuk satu proses). Multi-proses wajib injeksi `replay_store`.
4. **Hybrid ML-DSA belum didukung** di SDK v1; `sign_alg='hybrid-mldsa44-ed25519'` ditolak fail-closed saat konstruksi.
5. Penamaan opsi snake_case (`hmac_secret_raw`, dst.) — padanan langsung camelCase node-sdk/PHP.
