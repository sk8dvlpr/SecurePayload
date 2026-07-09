# SecurePayload — Roadmap Pengembangan

Dokumen ini adalah **source of truth** untuk roadmap library. Skill agent merujuk ke file ini: `.claude/skills/securepayload/securepayload-roadmap/SKILL.md`.

**Versi library saat ini:** 2.7.0  
**Versi protokol default:** `3` (`SecurePayload::DEFAULT_VERSION`)

---

## Status Phase

| Phase | Fitur | Versi | Status |
|-------|-------|-------|--------|
| 1 | Core protocol (HMAC / AEAD / BOTH, anti-replay, KMS dasar) | 1.0.0 | ✅ Done |
| 1b | Ed25519 request signing (`signAlg`) | 2.0.0 | ✅ Done |
| 2 | Response two-way (`buildResponse`, `verifyResponse`) | 2.1.0 | ✅ Done |
| 3 | AAD binding (timestamp + `bindHeaders`) | 2.2.0 | ✅ Done |
| 4 | PSR-16 replay store adapter | 2.3.0 | ✅ Done |
| 5 | HKDF subkey derivation (`deriveKeys`) | 2.4.0 | ✅ Done |
| 6 | File streaming AEAD (secretstream) | 2.5.0 | ✅ Done |
| 7 | Cloud KMS (Vault, AWS) | 2.6.0 | ✅ Done |
| 8 | Observability hooks (`onSecurityEvent`) | 2.7.0 | ✅ Done |
| 9 | Ed25519 response signing (server keypair) | — | ✅ Done |
| 10 | Key rotation + grace period | — | ✅ Done |
| 11 | Spesifikasi protokol formal + test vectors | — | ✅ Done |
| 12 | Framework packages resmi (Laravel, Symfony, CI4, Slim) | — | ✅ Done |
| 13 | PSR-18 HTTP transport + CLI tooling | — | 📋 Planned |
| 14 | SDK lintas bahasa (Node.js, Go) | — | 📋 Planned |
| 15 | Enterprise ops (GCP/Azure KMS, metrics/Prometheus) | — | 📋 Planned |

---

## Phase 9 — Ed25519 Response Signing ✅ Done

**Tujuan:** Non-repudiation dua arah penuh. Response mengikuti `signAlg` (mirror request).

**Diimplementasikan:**
- `signAlg=ed25519`: server sign response dengan `ed25519SecretKeyServerB64`; client verify dengan `ed25519PublicKeyServerB64`
- `signAlg=hmac` (default): perilaku HMAC response tidak berubah
- KMS: `EnvKeyProvider`, `DbKeyProvider` (`useEd25519Server`), `KeyManager::generateEd25519ServerKeyPair()`
- Client tidak butuh `hmacSecretRaw` untuk verifikasi response saat `signAlg=ed25519`

---

## Phase 10 — Key Rotation + Grace Period ✅ Done

**Tujuan:** Rotasi kunci produksi tanpa downtime client–server.

**Diimplementasikan:**
- Multiple `key_id` per `client_id` dengan kolom `status` + `valid_until`
- `DbKeyProvider` + `useKeyLifecycle=true` (opt-in, backward compatible)
- `KeyManager::rotateKey()`, `revokeKey()`, `purgeExpiredRetiringKeys()`
- `KeyRotationResult` + SQL migrasi (`toSqlUpdateRetiring`, `toSqlInsertNew`)
- Dokumentasi: `docs/KEY_ROTATION.md`, `docs/migrations/001_key_lifecycle.sql`
- Wire protocol tidak berubah; client tetap kirim `X-Key-Id` eksplisit

---

## Phase 11 — Spesifikasi Protokol + Test Vectors ✅ Done

**Tujuan:** Fondasi interoperabilitas lintas bahasa.

**Diimplementasikan:**
- `docs/PROTOCOL.md` — spesifikasi byte-exact v3 (canonicalization, HMAC, AEAD, AAD, response, HKDF)
- `docs/fixtures/v3/` — primitive, wire, dan negative JSON vectors + `schema.json`
- `tools/generate-protocol-fixtures.php` — regenerasi deterministik dari implementasi PHP
- `tests/Conformance/` — PHPUnit suite (portable ke Node/Go)
- Hook determinisme: `clock`, `nonceGenerator`, `respNonceGenerator` di `SecurePayload`

---

## Phase 12 — Framework Packages Resmi ✅ Done

**Tujuan:** Turunkan friction adopsi; `examples/` → package Composer terpisah.

**Diimplementasikan:**
- Monorepo `packages/`: `sk8dvlpr/securepayload-laravel`, `-symfony`, `-ci4`, `-slim`
- `SecurePayloadFactory` per framework (server/client, protocol v3 default)
- Server: Laravel middleware, Symfony subscriber, CI4 filter, Slim PSR-15 middleware
- Client: outgoing HTTP wrapper per framework
- Laravel: `securepayload:generate-keys`, `securepayload:rotate-key` Artisan commands
- Config publish / env template; CI matrix job untuk package tests

**Prasyarat:** Core library stabil (Phase 9–10 selesai atau frozen).

---

## Phase 13 — PSR-18 Transport + CLI

**Tujuan:** Lepas ketergantungan `send()` pada cURL; tooling operasional.

**Lingkup:**
- Interface transport / PSR-18 `ClientInterface`
- Binary `securepayload` CLI: `keys:generate`, `debug:verify`, `test:roundtrip`

**Prasyarat:** Tidak blocking fitur keamanan.

---

## Phase 14 — SDK Lintas Bahasa

**Tujuan:** Partner non-PHP bisa implement protokol.

**Lingkup:**
- SDK Node.js/TypeScript (prioritas 1)
- SDK Go (prioritas 2)
- Conformance suite dari Phase 11

**Prasyarat:** **Wajib** Phase 11 (spesifikasi + test vectors).

---

## Phase 15 — Enterprise Operations

**Tujuan:** Adopsi enterprise / multi-cloud.

**Lingkup:**
- `GcpKms`, `AzureKeyVaultKms` (ikuti pola `AwsKms`/`VaultKms`)
- Exporter metrics Prometheus via `onSecurityEvent`
- Opsional: OpenTelemetry spans

**Prasyarat:** Interface `Kms` sudah pluggable (Phase 7).

---

## Di Luar Scope (Jangan Tambahkan ke Library)

- OAuth 2.0 / OIDC server
- API gateway penuh
- User session management
- Algoritma lemah (AES-CBC, HS256 JWT-style, MD5, SHA-1)

---

## Urutan Implementasi yang Disarankan

```
Phase 9 → Phase 10 → Phase 11 → Phase 12 + 13 (paralel) → Phase 14 → Phase 15
```

**Refactor internal** (`SecurePayload.php` → modul terpisah): disarankan **sebelum atau bersamaan** Phase 9, saat menyentuh response signing dan key rotation.

---

## Changelog Protocol

Setiap phase selesai:
1. Update tabel status di file ini
2. Entri `CHANGELOG.md` dengan label phase
3. Update `CLAUDE.md` jika invariant/API berubah
4. Update skill `securepayload-architecture` jika ada entry point baru
5. Jalankan full test suite + `detect_changes()` sebelum commit
