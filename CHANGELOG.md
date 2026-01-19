# Changelog

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
