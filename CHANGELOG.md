# Changelog

## [Unreleased]
### Added
- **Milestone M6 — Dashboard admin MVP (`docs/DASHBOARD.md`)**:
  - `src/Observability/JsonlSecurityEventExporter.php`: persistensi JSONL
    append-only untuk `onSecurityEvent` — satu event = satu baris
    `{"ts","event","ctx"}`; append atomik (`flock LOCK_EX`), rotasi by-size
    opsional ke `<path>.N` (`maxSizeBytes`, `maxFiles` default 3), clock
    injectable; semantik EventEmitter: gagal I/O tidak pernah throw,
    tersedia via `getLastError()`.
  - Viewer read-only `examples/dashboard/index.php` (tanpa framework/JS):
    jumlah per tipe event, jumlah per client_id dari ctx, N event terakhir
    (default 100), panel umur KEK (hanya nama dari env `SECURE_KEKS` +
    `<id>_CREATED_AT` — nilai secret tidak pernah dirender). Semua output
    di-escape (`htmlspecialchars`); path log HANYA dari env `SP_EVENT_LOG`
    (bukan query param); metode selain GET/HEAD ditolak; tail-read dibatasi
    8 MiB. Placeholder HTTP basic-auth + warning wajib-auth di belakang
    reverse proxy.
  - Tests: `tests/Unit/JsonlSecurityEventExporterTest.php` (11 test).
  - Wire protocol v3/v4 tidak berubah (murni observability + contoh).

- **Milestone M1 — Watermark forensik `retrieveStream()` (plan §5.4)**:
  - Opsi `beforeStream` di `SecureFileStorage::retrieveStream($m, $sink, $opts)`:
    hook `callable(string $plain, FileManifest $m, array $ctx): string` menerima
    plaintext penuh lalu mengembalikan plaintext terwatermark (`$ctx = ['file_id', 'requester']`,
    konteks peminta via opsi `requester`). Library tetap PDF-agnostic.
  - Fail-closed: hook jalan SEBELUM chunk pertama — exception dipropagasi sebagai
    SERVER_ERROR (previous ter-chain) setelah event `file_watermark_failed`;
    return non-string / beforeStream non-callable / requester non-array → BAD_REQUEST;
    NOL byte body terkirim saat gagal. Plaintext kosong tetap memanggil hook.
  - Event baru: `EVENT_FILE_WATERMARKED` (`file_watermarked`, konteks `file_id`)
    dan `EVENT_FILE_WATERMARK_FAILED` (`file_watermark_failed`, konteks `file_id`);
    dikenali di PrometheusSecurityExporter + OpenTelemetrySecurityExporter.
  - `composer suggest += mpdf/mpdf`; docs: FILE_STORAGE.md (section Watermark
    Forensik), SECURE_DELIVERY.md (contoh nyata), example endpoint (SP_WATERMARK=1).
  - `retrieve()` tidak di-hook pada v1 (restore/arsip internal, bukan jalur distribusi).

- **Milestone 5 — Compression, payloadSchema, Idempotency (opt-in penuh)**:
  - Kompresi payload client (D10): `src/Compression/PayloadCompressor.php`
    - Opsi konstruktor `compress => true` (default **false**); gzip/brotli (fallback otomatis ke gzip bila ekstensi brotli tidak ada), skip otomatis body < 1024 byte atau rasio hasil ≥ 95% (`identity`).
    - Header `X-Payload-Encoding: gzip|br|identity` selalu eksplisit saat fitur aktif; digest & HMAC dihitung atas **byte terkompresi**.
    - Server mendekompresi HANYA setelah seluruh verifikasi integritas (digest/HMAC/AEAD) lolos; guard decompression-bomb streaming 8 MiB (hasil > batas → 422); encoding tak dikenal → 400 fail-closed.
  - Validasi skema payload server (D11): `src/Protocol/PayloadSchemaValidator.php`
    - Opsi konstruktor `payloadSchema` (array non-kosong; subset JSON Schema: type/properties/required/items/enum/minimum/maximum/minLength/maxLength/minItems/maxItems/pattern/additionalProperties + maxDepth 16).
    - Gagal validasi → event `payload_schema_invalid` + status 422 fail-closed. Tanpa `payloadSchema`, perilaku existing dipertahankan.
  - Store idempotensi (D12): `src/Idempotency/{IdempotencyStoreInterface,ArrayIdempotencyStore,Psr16IdempotencyStore}.php`
    - Terpisah dari anti-replay dan TIDAK digabung ke RequestVerifier; Psr16 adapter tanpa klaim atomicity.

### Notes
- Wire protocol v3/v4 **tidak berubah**: tanpa opsi baru di atas, tidak ada header tambahan dan byte wire identik (Conformance fixtures tidak diregenerasi).
- Sinkronisasi wajib saat mengaktifkan kompresi: client DAN server harus menjalankan versi ≥ Milestone 5.

## [3.2.0] - 2026-08-26
Rilis yang sama dengan [Unreleased] di atas (Milestone M1 watermark forensik, M5 compression/payloadSchema/idempotency, M6 dashboard admin, key lifecycle + destroy, secure file storage & delivery, observability JSONL, CLI doctor, SDK Python/RN/Kong/Envoy). Tidak ada perubahan wire protocol v4; sepenuhnya backward compatible terhadap 3.1.x.

## [3.1.0] - 2026-07-10
### Added
- **Post-quantum hybrid signing (Phase 18d)**:
  - `signAlg` = `hybrid-mldsa44-ed25519` (`SecurePayload::SIGN_ALG_HYBRID`)
  - Header algorithm `HYBRID-MLDSA44-ED25519` — wire: `base64(ed25519_sig ‖ mldsa_sig)`
  - `SecurePayload\Crypto\PqSignerInterface` + opsi konstruktor `pqSigner` (wajib untuk hybrid)
  - Field kunci: `mldsaSecretKeyB64`, `mldsaPublicKeyB64`, `mldsaSecretKeyServerB64`, `mldsaPublicKeyServerB64`
  - `docs/POST_QUANTUM.md`

### Notes
- Opt-in; tanpa `pqSigner` konstruktor gagal. Stub tes bukan kriptografi PQ nyata.

## [3.0.0] - 2026-07-10
### Changed
- **Wire protocol v4 (Phase 18c)** — `SecurePayload::DEFAULT_VERSION = '4'` (breaking default).
  - Non-file JSON sama seperti v3; label HKDF/AAD memakai string versi `"4"`.
  - Satu instance hanya menerima versi yang dikonfigurasi (tidak dual-accept).
  - Gunakan `version => '3'` untuk kompatibilitas eksplisit.

### Added
- Multipart file stream: `buildFileStreamMultipartRequest()` / `verifyFileStreamMultipart()`
  - Body HTTP: parts `payload` (body SP manifest) + `ciphertext`; header `X-SP-Multipart: 1`
- `docs/fixtures/v4/` (primitive minimal) + `V4PrimitiveVectorsTest`
- Node/Go SDK: `DEFAULT_VERSION` / `DefaultVersion` = `"4"`

## [2.11.0] - 2026-07-10
### Added
- **RFC 9421 bridge (Phase 18b)**: `SecurePayload\Interop\Rfc9421Bridge`
  - `exportFromSecureHeaders()` → `Signature-Input` / `Signature` / `Content-Digest`
  - `verifyMapped()` — validasi digest + komponen wajib, lalu `SecurePayload::verify()`
  - `docs/RFC9421_BRIDGE.md`, `examples/interop/rfc9421.php`

### Notes
- Aditif; tidak mengubah wire SP. Go middleware (Phase 18a) di `packages/go-sdk/middleware`.

## [2.10.0] - 2026-07-10
### Added
- **Ekosistem & Observability (Phase 17)**:
  - `SecurePayload\Webhook\WebhookVerifier` — helper verifikasi webhook (`verifyFromGlobals`, `verifyFromRequest`)
  - `SecurePayload\Observability\OpenTelemetrySecurityExporter` — span OpenTelemetry dari `onSecurityEvent` (opsional, duck typing tracer)
  - Node SDK: middleware Express (`verifySecurePayload`) dan plugin Fastify (`fastifySecurePayloadPlugin`)
  - `docs/MTLS_DEPLOYMENT.md` — panduan mTLS + SecurePayload (transport vs aplikasi)
  - Contoh: `examples/webhook/verify.php`, `examples/observability/opentelemetry.php`

### Notes
- Murni aditif: **tidak mengubah format wire** protokol v3. `open-telemetry/sdk`, `express`, `fastify` opsional.

## [2.9.0] - 2026-07-10
### Changed
- **Refactor Core (Phase 16)** — modularisasi internal `SecurePayload.php` tanpa mengubah wire protocol v3:
  - `src/Protocol/` — `Canonical`, `Digest`, `Messages`, `Aead`, `Hkdf` (static helpers; facade tetap delegasi via `SecurePayload::…`)
  - `src/Internal/SecurePayloadConfig.php` — state konstruktor + helper kriptografi bersama
  - `src/Client/RequestBuilder.php` — `buildHeadersAndBody`
  - `src/Server/RequestVerifier.php`, `ReplayGuard.php` — verifikasi request + anti-replay
  - `src/Response/ResponseBuilder.php`, `ResponseVerifier.php`
  - `src/File/` — `FilePayloadService`, `FileStreamService`, `FileValidation`
  - `src/SecurePayload.php` — facade tipis (~400 baris): konstanta publik + delegasi

### Notes
- **Tidak ada breaking change** pada API publik atau format wire v3. Framework packages tidak perlu diubah.

## [2.8.0] - 2026-07-09
### Added
- **Enterprise Operations (Phase 15)** — adapter KMS multi-cloud dan exporter Prometheus:
  - `SecurePayload\KMS\GcpKms` — GCP Cloud KMS (`additionalAuthenticatedData` binding AAD context). Dependency opsional: `google/cloud-kms`.
  - `SecurePayload\KMS\AzureKeyVaultKms` — Azure Key Vault Cryptography (`additionalAuthenticatedData`). Dependency opsional: `azure/keyvault-keys`.
  - `SecurePayload\Observability\PrometheusSecurityExporter` — counter `securepayload_security_events_total` dari hook `onSecurityEvent`; label `client_id`/`key_id` opt-in (cardinality).
  - Contoh: `examples/observability/prometheus.php`.

### Notes
- Murni aditif: **tidak mengubah format wire** protokol v3. OpenTelemetry ditunda ke backlog.

## [2.7.1] - 2026-07-09
### Added
- **Cross-Language SDKs (Phase 14)** — SDK Node.js/TypeScript dan Go untuk protokol v3 (byte-exact):
  - `packages/node-sdk` — API `buildHeadersAndBody`, `verify`, `buildResponse`, `verifyResponse`; conformance v3 + interop PHP; CI job `node-sdk`
  - `packages/go-sdk` — mirror Node/PHP; primitive + wire + negative conformance; smoke interop Go↔PHP; CI job `go-sdk`

### Notes
- Tidak mengubah wire format PHP core (`sk8dvlpr/securepayload` tetap v2.7.x). SDK terpisah di monorepo.

## [2.7.0] - 2026-06-23
### Added
- **Observability & Audit Hooks (Phase 8)** — opsi konstruktor `onSecurityEvent: fn(string $event, array $context): void` untuk meneruskan event keamanan ke SIEM / rate-limiter.
  - Event diemit pada: timestamp di luar batas (`timestamp_invalid`), replay terdeteksi (`replay_detected`), dekripsi gagal (`decrypt_failed`), signature invalid (`signature_invalid`), key tidak ditemukan (`key_not_found`), dan nonce mismatch (`nonce_mismatch`) — tersedia sebagai konstanta `SecurePayload::EVENT_*`.
  - Context event hanya memuat data non-rahasia (`clientId`/`keyId` + penanda ringan) — **tidak pernah** secret, plaintext, atau ciphertext.

### Notes
- Murni aditif & observasional: **tidak mengubah alur/keamanan verifikasi** maupun format wire. Exception dari callback ditelan agar observability tidak pernah memengaruhi verifikasi.

## [2.6.0] - 2026-06-22
### Added
- **Adapter Cloud KMS (Phase 7)** — implementasi `Kms` (`wrap()`/`unwrap()`) untuk penyedia terkelola:
  - `SecurePayload\KMS\VaultKms` — HashiCorp Vault **Transit** engine (token auth, transport HTTP injectable, default cURL). AAD context dipetakan ke parameter `context` Transit (memerlukan kunci `derived=true`).
  - `SecurePayload\KMS\AwsKms` — membungkus `Aws\Kms\KmsClient` (dependensi opsional). AAD context dipetakan ke **EncryptionContext** AWS KMS.
- Kedua adapter menjaga kontrak AAD context `['client_id','key_id','purpose']`, konsisten dengan `LocalKms`, dan langsung dapat di-inject ke `DbKeyProvider`/`KeyManager`.
- `aws/aws-sdk-php` ditambahkan ke `suggest` (opsional, tidak masuk core).

### Notes
- **Tidak mengubah format wire** — hanya mekanisme *wrap/unwrap* kunci AEAD di server. Aditif murni; tidak ada kenaikan `version`.

## [2.5.0] - 2026-06-22
### Added
- **Streaming AEAD untuk file besar (Phase 6)**: API baru `buildFileStream()` / `verifyFileStream()` yang memproses file **per-chunk** memakai XChaCha20-Poly1305 *secretstream* — tanpa memuat seluruh file ke memori (berbeda dari `buildFilePayload()` yang base64 in-memory).
  - `buildFileStream(src, dest, meta, chunkSize=64KiB)` menulis ciphertext ber-frame ke `dest` dan mengembalikan **manifest** kecil (nama, ukuran, MIME, header secretstream, digest ciphertext) untuk dikirim & ditandatangani lewat jalur request biasa.
  - `verifyFileStream(enc, manifest, dest, constraints)` mendekripsi per-chunk dengan validasi keamanan file yang sama (`max_size`, `allowed_exts`, `block_dangerous`, `strict_mime` magic-byte sniffing).
  - Kunci stream diturunkan dari AEAD key instance; mendukung opsi `deriveKeys` (purpose `sp-aead-stream`).
  - Contoh `examples/file-stream/` (sender + receiver).

### Security
- Proteksi **truncation & append**: penanda akhir `TAG_FINAL` wajib ada dan tunggal; data setelahnya ditolak.
- **Digest ciphertext** dicocokkan terhadap manifest yang sudah ditandatangani; tiap chunk diautentikasi tag Poly1305.
- **GAGAL-TERTUTUP**: bila verifikasi gagal di tahap mana pun, file plaintext parsial di `dest` otomatis dihapus.

### Changed
- Logika validasi ekstensi & MIME file diekstrak menjadi helper bersama (dipakai `verifyFilePayload` dan `verifyFileStream`) — perilaku & pesan error tidak berubah.

## [2.4.0] - 2026-06-22
### Added
- **Derivasi subkey via HKDF (Phase 5)**: opsi opt-in `deriveKeys: bool`. Bila aktif, kunci HMAC & AEAD yang disuplai diperlakukan sebagai **master key** dan subkey per-fungsi diturunkan via `hash_hkdf('sha256', ...)`. Pemisahan domain: enkripsi request, enkripsi response, signing request, dan signing response masing-masing memakai subkey berbeda (`sp-aead-req`, `sp-aead-resp`, `sp-sign-req`, `sp-sign-resp`), sehingga kompromi satu subkey tidak meruntuhkan fungsi lain.
  - Helper publik `SecurePayload::deriveKey(string $master, string $purpose, int $len = 32): string` untuk derivasi HKDF terdokumentasi.
  - Label `info` HKDF diikat ke versi protokol (`...|v{version}`), sehingga subkey otomatis berbeda antar versi.
  - **Tidak** berlaku untuk signing Ed25519 (sudah asimetris) — hanya HMAC & AEAD yang diturunkan.

### Security
- `deriveKeys` **WAJIB identik di client & server**. Konfigurasi yang tidak cocok GAGAL-TERTUTUP (signature/dekripsi invalid) — tidak ada jalur downgrade diam-diam.

### Notes
- Opt-in dan **backward-compatible**: default `deriveKeys = false` → kunci dipakai langsung, perilaku wire byte-identik dengan v2.3.0. Karena itu `DEFAULT_VERSION` tetap `'3'` (tidak ada kenaikan versi paksaan untuk fitur opsional). Saat diaktifkan, format efektif berubah; pastikan kedua sisi sinkron.

## [2.3.0] - 2026-06-19
### Added
- **Adapter replay-store PSR-16 (Phase 4)**: `SecurePayload\ReplayStore\Psr16ReplayStore` membungkus cache `Psr\SimpleCache\CacheInterface` apa pun menjadi callable `replayStore` (`fn(string $key, int $ttl): bool`). Bersifat *invokable* sehingga bisa langsung dipasang sebagai `replayStore`.
  - Memakai jalur **atomik** `add()` bila cache yang dibungkus menyediakannya; jatuh ke `has()+set()` (best-effort) untuk PSR-16 murni. Method `isAtomic()` untuk diagnostik.
- **Contoh replay-store siap pakai** di `examples/replay-store/`: `redis.php` (`SET NX`), `memcached.php` (`add()`), dan `psr16.php` (adapter bawaan), beserta dokumentasi jaminan atomicity.
- Dependensi opsional `psr/simple-cache` ditambahkan ke `suggest` (dan `require-dev` untuk pengujian) — **tidak** wajib bagi konsumen yang tidak memakai adapter ini.

### Notes
- Phase 4 bersifat **aditif murni** — tidak mengubah format wire maupun titik ekstensi `replayStore` yang sudah ada; tidak ada kenaikan `version` protokol.

## [2.2.0] - 2026-06-18
### Security
- **Binding timestamp ke AAD (Phase 3)**: `X-Timestamp` request kini selalu diikat ke AAD AEAD. Pada mode `aead` (yang tidak ditandatangani HMAC), manipulasi timestamp otomatis menggagalkan dekripsi — bukan hanya ditolak oleh validasi kesegaran.
- **Binding header kritikal ke AAD**: opsi konstruktor baru `bindHeaders: string[]` (mis. `['Content-Type']`). Nilai header yang terdaftar diikat ke AAD; perubahan **maupun penghapusan** nilainya menggagalkan dekripsi. Nama header diperlakukan case-insensitive dan diurutkan (`ksort`) agar AAD identik di client & server. Konfigurasi WAJIB sama di kedua sisi.
- **Binding timestamp response ke AAD**: `X-Resp-Timestamp` kini diikat ke AAD response, simetris dengan jalur request.

### Added
- Parameter opsional `$extraHeaders` pada `buildHeadersAndBody()` dan `buildFilePayload()` untuk memasok nilai header (termasuk yang diikat) di sisi client; juga ikut diteruskan oleh `send()`/`sendFile()`.

### Changed
- **Breaking Change (wire format)**: `DEFAULT_VERSION` dinaikkan dari `'2'` ke `'3'` karena format AAD berubah. Ciphertext lama (v2) tidak akan terdekripsi; client & server harus migrasi serempak. Binding timestamp/header ke AAD kini **tidak bersyarat** — menyetel `version` ke nilai lama hanya mengubah label versi, bukan mengembalikan perilaku AAD lama. Untuk tetap memakai protokol lama sepenuhnya, tahan pemutakhiran library.

## [2.1.0] - 2026-06-17
### Added
- **Pengamanan response dua arah** (Two-Way Integrity): `buildResponse()` (server) menghasilkan response tertanda tangan/terenkripsi, `verifyResponse()` / `verifyResponseOrThrow()` (client) memverifikasinya. Mengikuti mode instance (hmac/aead/both).
  - Response **diikat ke nonce request asal** (dimasukkan ke pesan kanonik & AAD, tidak ditransmisikan) sehingga tidak bisa dipindah (replay/relocation) ke konteks request lain.
  - Header response memakai namespace terpisah `X-Resp-*` agar tidak bentrok dengan header request.
  - Validasi kesegaran timestamp response dan anti-downgrade AEAD pada mode aead/both.
- **Catatan:** tanda tangan response memakai HMAC-SHA256 dengan secret bersama (bukan Ed25519), karena server tidak memegang private key client; pada mode aead/both autentisitas dijamin oleh AEAD tag. Tanda tangan response asimetris penuh (keypair server) menjadi kandidat phase berikutnya.

## [2.0.0] - 2026-06-17
### Added
- **Tanda tangan asimetris Ed25519** (`signAlg => 'ed25519'`): client menandatangani dengan secret key, server memverifikasi dengan public key (libsodium `crypto_sign`). Memberi *non-repudiation* dan memperkecil blast-radius bila kunci server bocor (server tidak lagi bisa memalsukan request client). HMAC (`signAlg => 'hmac'`) tetap default.
  - Opsi konstruktor baru: `signAlg`, `ed25519SecretKeyB64` (client).
  - `keyLoader`/provider kini dapat mengembalikan `ed25519PublicKeyB64` (server).
  - `KeyManager::generateEd25519KeyPair()` untuk membangkitkan pasangan kunci.
  - `EnvKeyProvider`: membaca `SECUREPAYLOAD_{CID}_{KID}_ED25519_PUBLIC_B64`.
  - `DbKeyProvider`: kolom opsional `ed25519_public_b64` (aktifkan via `opts['useEd25519'] = true`).

### Security
- Algoritma tanda tangan ditentukan oleh konfigurasi server (`signAlg`), **bukan** dari header `X-Signature-Algorithm`. Header yang tidak cocok ditolak — mencegah downgrade tanda tangan (Ed25519 ↔ HMAC).

### Changed
- **Breaking Change**: `DEFAULT_VERSION` dinaikkan dari `'1'` ke `'2'`. Client dan server harus memakai versi protokol yang sama; lakukan migrasi serempak. Pengguna yang ingin tetap di protokol lama dapat menyetel `version => '1'` secara eksplisit di kedua sisi.

## [1.3.0] - 2026-01-20
### Added
- **File Upload Support**: Added secure file transfer capabilities.
  - `buildFilePayload($url, $method, $filePath, [$data])`: Create payload with Base64 encoded file.
  - `sendFile(...)`: Wrapper to send file securely in one line.
  - `verifyFilePayload(...)`: Server-side verification including size limit, extension checking, and **Strict MIME-Type Sniffing** to prevent extension spoofing.
- **Enhanced Payload**: The library now supports encapsulating file attachments within the secure JSON payload.

## [1.2.0] - 2026-01-20
### Security
- **[CRITICAL]** Fixed signature spoofing vulnerability in `verifySimple()`. The method now REQUIRES `$method` and `$path` parameters to be passed explicitly from the server's context, instead of trusting the `X-Canonical-Request` header.
- Fixed race condition in default file-based replay protection using `flock`.

### Added
- **KeyManager**: New utility class in `src/KMS/KeyManager.php` to simplified key generation, wrapping (encryption), and SQL export for multi-client setups.
- **Native PHP Example**: Added `examples/native/` demonstrating usage without frameworks.
- **Detailed Examples**: Added companion "Sender" (Client) examples for all frameworks (CI4, Laravel, Lumen, Slim, Symfony).

### Changed
- Refactored codebase to comply with **PSR-12** standards.
- Updated all Code Documentation (PHPDoc) to **Indonesian** language for better clarity.
- **Breaking Change**: `verifySimple` signature changed from `verifySimple($headers, $body)` to `verifySimple($headers, $body, $method, $path)`.

## [1.1.1] - 2025-09-23
### Added
- Unit tests untuk API `verifySimple()`:
  - HMAC / AEAD / BOTH happy path
  - Missing `X-Canonical-Request`
  - Replay detection dengan custom `replayStore`
  - Timestamp out-of-range (HMAC; rekalkulasi signature agar isolasi error timing)
  - AEAD nonce mismatch (BOTH)
  - Body digest mismatch (HMAC)
  - Signature mismatch (HMAC)

### Notes
- Test AEAD/BOTH otomatis `markTestSkipped` jika `ext-sodium` tidak tersedia.
- Semua test menggunakan API simple (`verifySimple($headers, $rawBody)`).

## [1.1.0] - 2025-09-23
### Added
- API simple verification: `verifySimple()` dan `verifySimpleOrThrow()` (server cukup headers + body).
- Header `X-Canonical-Request` (METHOD\nPATH\nQUERY) ditambahkan oleh client.

## [1.0.0] - 2025-09-01
### Added
- Rilis awal: HMAC / AEAD / BOTH, anti-replay, key via ENV/DB, LocalKms, unit test & CI.
