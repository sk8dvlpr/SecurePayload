---
name: securepayload-security-review
description: Security review checklist for SecurePayload changes touching signing, verification, replay protection, AEAD, or key management. Use when reviewing PRs, auditing crypto code, or before merging changes to verify/build/sign paths.
---

# SecurePayload — Security Review

Apply this checklist to **any** change touching `SecurePayload.php`, KMS, or replay store.

## Critical Invariants

| # | Invariant | Violation test |
|---|-----------|----------------|
| 1 | Server uses **its own** `$method`, `$path`, `$query` — never `X-Canonical-Request` | `SignatureSpoofingTest` |
| 2 | Replay key = `hash(clientId\|keyId\|nonce)` — **no timestamp** in key | `DowngradeAndReplayTest` |
| 3 | Nonce TTL = `replayTtl + clockSkew` (full freshness window) | `DowngradeAndReplayTest` |
| 4 | HMAC signs **plaintext** in `both` mode | `SecurePayloadTest`, crypto binding tests |
| 5 | AEAD nonce from `aeadNonceFrom()` bound to method/path/query | `CryptoBindingTest`, `AadBindingTest` |
| 6 | All comparisons use `hash_equals` | Code review |
| 7 | `signAlg` from **server config**, reject header mismatch | `Ed25519SigningTest`, downgrade tests |
| 8 | Mode `both` cannot downgrade to HMAC-only silently | `DowngradeAndReplayTest` |
| 9 | `deriveKeys` mismatch → fail closed (invalid sig/decrypt) | `HkdfMismatchTest` |
| 10 | `bindHeaders` + timestamp always in AAD (v3) | `AadBindingTest` |
| 11 | Response `X-Resp-Signature-Algorithm` must match `signAlg` config | `Ed25519ResponseSigningTest` |
| 12 | Response tied to **request nonce** | `ResponseSecurityTest` |
| 13 | Ed25519 response: server keypair distinct from client; no HMAC for response verify | `Ed25519ResponseSigningTest` |
| 14 | `onSecurityEvent` never leaks secrets; callback exceptions swallowed | `SecurityEventTest` |

## Review Checklist

```
Authentication & signing
- [ ] HMAC secret validated ≥ 32 chars at construct and keyLoader
- [ ] Ed25519 keys correct length (64-byte secret, 32-byte public)
- [ ] Signature verified after decrypt in `both` mode (plaintext input)
- [ ] No timing-unsafe comparisons (==, strcmp on secrets)

Encryption
- [ ] ensureSodium() called before AEAD operations
- [ ] AEAD key exactly 32 bytes
- [ ] AAD includes version-bound fields per protocol v3
- [ ] Unique nonce per encryption (derived, not random reuse)

Replay
- [ ] Timestamp: reject future > clockSkew, past > replayTtl + clockSkew
- [ ] replayStore returns true only for NEW nonce
- [ ] File-based default store documented as single-host only

Key management
- [ ] DbKeyProvider SQL identifiers validated (^[A-Za-z_][A-Za-z0-9_]*$)
- [ ] SQL values always bound (no string interpolation of secrets)
- [ ] KMS AAD context ksorted + consistent wrap/unwrap

File handling
- [ ] verifyFilePayload: size, extension, strict_mime when enabled
- [ ] verifyFileStream: TAG_FINAL, ciphertext digest, partial file cleanup on failure

Observability
- [ ] onSecurityEvent context has no plaintext/ciphertext/secrets
- [ ] Hook failure does not affect verify outcome
```

## Tests to Run by Area

| Area changed | Minimum tests |
|--------------|---------------|
| `verify*` / `buildHeaders*` | `Unit` + `Security` full |
| Replay / timestamp | `DowngradeAndReplayTest`, `ReplayAndSecurityTest` |
| AAD / bindHeaders | `AadBindingTest` |
| Response signing | `ResponseSecurityTest`, `ResponseRoundTripTest`, `Ed25519ResponseSigningTest` |
| HKDF | `HkdfDeriveKeyTest`, `HkdfMismatchTest`, `HkdfRoundTripTest` |
| File stream | `FileStreamSecurityTest`, `FileStreamRoundTripTest` |
| Ed25519 | `Ed25519SigningTest` |
| KMS | `LocalKmsTest`, `DbKeyProviderTest`, `VaultKmsTest`, `AwsKmsTest` |

```bash
vendor/bin/phpunit --testsuite Security
composer test
```

## Red Flags (Reject or Fix)

- `verifySimple` or any verify path reading canonical data from headers
- Timestamp added to replay cache key
- Shorter replay TTL than `replayTtl + clockSkew`
- Trusting `X-Signature-Algorithm` from client to select verifier
- Logging full request body, secrets, or decrypted payload in production hooks
- New `==` comparison on HMAC/signature/nonce
- AEAD with empty or static nonce
- Skipping replay check in any successful verify path

## Wire Format Changes

If PR changes ciphertext, AAD layout, or signature message format:

1. **Must** document in CHANGELOG as breaking or version-gated
2. **Must** bump `DEFAULT_VERSION` or require explicit `version` opt-in
3. **Must** add Security regression test proving old attack still blocked
4. **Must** update roadmap/docs if part of a phase

## Production Deployment Review

For integration changes (middleware, examples):
- [ ] HTTPS assumed (documented, not optional in examples)
- [ ] `replayStore` Redis/Memcached for multi-server
- [ ] `deriveKeys` / `bindHeaders` / `version` / `mode` identical on both sides
- [ ] `keyLoader` does not log returned secrets

## Escalation

For HIGH/CRITICAL GitNexus impact on `verify`, `checkReplay`, `hmacMessage`, `aeadNonceFrom`, or `buildHeadersAndBody`: warn user before proceeding; suggest Security suite run and manual threat review.
