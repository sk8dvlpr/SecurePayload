# Changelog

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
