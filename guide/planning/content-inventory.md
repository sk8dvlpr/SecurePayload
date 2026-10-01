# Content Inventory — SecurePayload User Guide

Sumber diverifikasi dari repo pada 2026-09-30. Audit: `audit/REPORT.md` + `audit/VERIFY.md`.

## Versi aktual

| Item | Nilai | Sumber |
|------|-------|--------|
| Package | sk8dvlpr/securepayload | composer.json |
| Library | 3.2.0 | composer.json, CHANGELOG |
| Protocol default | 4 | SecurePayload::DEFAULT_VERSION |
| License | MIT | composer.json |
| PHP require | >=8.0 | composer.json |
| CI matrix | 8.0–8.5 | .github/workflows/ci.yml |
| Third-party audit | Belum ada | audit/REPORT.md |

### Ketidakcocokan untuk pembaca

1. Protocol v4 default — samakan client dan server; gunakan `version => '3'` bila perlu.
2. Node/Go SDK `DEFAULT_VERSION = '4'` (fixtures v3 tetap ada).
3. README response masih bilang selalu HMAC; kode mengikuti `signAlg`. Panduan mengikuti kode.
4. `requireReplayStore` ada di kode/`SECURITY.md`, belum di tabel README.
5. PHP 8.5 teruji di CI; tulis jujur tanpa klaim audit manual 8.5 lokal.

## Requirements

- Wajib: PHP >= 8.0, `ext-json`, `ext-hash`
- Untuk `aead`/`both`/Ed25519/stream: `ext-sodium`
- Opsional: `ext-curl`, PSR-18, PSR-16, cloud KMS SDKs, OTel
- Hybrid ML-DSA: `pqSigner` disuplai aplikasi (tidak dibundle)

## Mode dan kunci

- `hmac` = tanda tangan saja; `aead` = kunci saja; `both` = keduanya (default)
- `signAlg`: `hmac` | `ed25519` | `hybrid-mldsa44-ed25519`
- Response mengikuti `signAlg` (HMAC bersama, atau keypair **server** Ed25519/hybrid)
- Defaults: `replayTtl=120`, `clockSkew=60`, `deriveKeys=false`, `compress=false`, `requireReplayStore=false`

## Opsi konstruktor

`mode`, `signAlg`, `version`, `clientId`, `keyId`, `hmacSecretRaw`, `aeadKeyB64`, `ed25519*`, `mldsa*`, `pqSigner`, `keyLoader`, `replayStore`, `requireReplayStore`, `replayTtl`, `clockSkew`, `bindHeaders`, `deriveKeys`, `compress`, `payloadSchema`, `onSecurityEvent`, `httpTransport`, `clock`, `nonceGenerator`, `respNonceGenerator`

## Method publik

**Client:** `buildHeadersAndBody`, `send`, `buildFilePayload`, `sendFile`, `buildFileStream`, `buildFileStreamMultipartRequest`, `verifyResponse`, `verifyResponseOrThrow`

**Server:** `verify`, `verifyOrThrow`, `verifySimple`, `verifyFilePayload`, `verifyFileStream`, `verifyFileStreamMultipart`, `buildResponse`

**Static:** `deriveKey`, `normalizePath`, `canonicalQuery`, `genNonceB64`, `bodyDigestB64`, `buildRequestAeadAad`, `buildResponseAeadAad`, `aeadNonceFrom`, `hmacMessage`, `respAeadNonceFrom`, `respMessage`

## Headers

Request: `X-Client-Id`, `X-Key-Id`, `X-Timestamp`, `X-Nonce`, `X-Signature-Version`, `X-Signature-Algorithm`, `X-Signature`, `X-Body-Digest`, `X-Canonical-Request` (debug only), `X-AEAD-*`, `X-Payload-Encoding`, `X-Idempotency-Key`, `X-SP-Multipart`

Response: `X-Resp-*` mirror

## Events

`timestamp_invalid`, `replay_detected`, `decrypt_failed`, `signature_invalid`, `key_not_found`, `nonce_mismatch`, `file_stored`, `file_accessed`, `file_access_denied`, `file_deleted`, `file_watermarked`, `file_watermark_failed`, `payload_schema_invalid`

## Exception codes

400 / 401 / 422 / 500 + `context` → `verify()` `debug`

Pesan inti: Header keamanan tidak lengkap; Versi protokol tidak didukung; Format timestamp salah; Timestamp di luar batas wajar; Replay detected; Payload AEAD tidak ditemukan; Nonce mismatch; Gagal mendekripsi; Integritas Body Digest gagal; Tanda Tangan tidak valid; HMAC Secret terlalu pendek; Kunci AEAD tidak valid; Ekstensi sodium diperlukan; clientId & keyId wajib; requireReplayStore tanpa store.

## Fitur untuk dokumentasi

Anti-replay, response dua arah, file kecil, streaming, multipart, webhook, Ed25519, hybrid PQ, deriveKeys, bindHeaders, observability, RFC 9421, Node/Go SDK, CLI, mTLS, KMS, key rotation/lifecycle, file storage/delivery, idempotency/compress/payloadSchema

## Framework & packages

Examples: Native, CI4, Laravel, Lumen, Slim, Symfony.

Packages: laravel, symfony, ci4, slim, cli, node-sdk, go-sdk, python-sdk, rn-sdk, kong-plugin, envoy-authz.

CLI: `keys:generate`, `keys:rotate`, `debug:verify`, `test:roundtrip`, `doctor`.

## Peringatan publik (tanpa detail exploit)

**Wajib:** samakan version; method/path/query dari server; `replayStore` + `requireReplayStore` multi-server; HTTPS; `signAlg` server-side; HMAC ≥32 / AEAD 32 byte; `deriveKeys`/`bindHeaders` match; private Ed25519 request tidak di server; sanitasi filename; jangan log secret; jangan http produksi.

**Hati-hati:** Vault `derived=true`; PSR-16 `requireAtomic`; EnvKeyProvider `[A-Za-z0-9_]`; CLI mask secrets; `pqSigner` wajib hybrid; mode hmac tidak enkripsi; file in-memory ≤ ~10 MB; LocalKms untuk dev; jendela replay = `replayTtl + clockSkew`.

**Saran:** belum audit pihak ketiga; HTTP status/Content-Type response belum diikat ke wire (batasan desain).
