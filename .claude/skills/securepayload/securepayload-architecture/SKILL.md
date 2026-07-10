---
name: securepayload-architecture
description: Explains SecurePayload library architecture, execution flows, modules, and security invariants. Use when understanding how the library works, tracing client/server flows, onboarding contributors, or answering "how does X work?" for SecurePayload.
---

# SecurePayload — Architecture

## What This Library Is

`sk8dvlpr/securepayload` — framework-agnostic PHP 8.0+ library for securing S2S HTTP requests: HMAC-SHA256 or Ed25519 signing, XChaCha20-Poly1305 AEAD encryption, anti-replay. Single class acts as **both** client and server depending on which methods are called.

**Current:** library v3.1.0, protocol `DEFAULT_VERSION = '4'`.

## Module Map

| Path | Role |
|------|------|
| `src/SecurePayload.php` | **Public facade** (~400 lines): constants, constructor, delegation; static helpers delegate to `Protocol/` |
| `src/Protocol/Canonical.php` | `normalizePath`, `canonicalQuery` |
| `src/Protocol/Digest.php` | `genNonceB64`, `bodyDigestB64` |
| `src/Protocol/Messages.php` | `hmacMessage`, `respMessage` |
| `src/Protocol/Aead.php` | AAD builders, `aeadNonceFrom`, `respAeadNonceFrom` |
| `src/Protocol/Hkdf.php` | `deriveKey` (HKDF-SHA256) |
| `src/Internal/SecurePayloadConfig.php` | Constructor state + shared crypto helpers (`deriveSubkey`, keys, `collectBoundHeaders`, `emitEvent`, hybrid sign/verify) |
| `src/Client/RequestBuilder.php` | `buildHeadersAndBody` |
| `src/Server/RequestVerifier.php` | `verifyOrThrow` |
| `src/Server/ReplayGuard.php` | Replay protection + nonce file GC |
| `src/Response/ResponseBuilder.php` | `buildResponse` |
| `src/Response/ResponseVerifier.php` | `verifyResponseOrThrow` |
| `src/File/FilePayloadService.php` | In-memory file (`buildFilePayload`, `verifyFilePayload`) |
| `src/File/FileStreamService.php` | Streaming file (secretstream) + multipart parse/build (v4) |
| `src/File/FileValidation.php` | Extension/MIME validation helpers |
| `src/Interop/Rfc9421Bridge.php` | RFC 9421 export/verifyMapped bridge |
| `src/Crypto/PqSignerInterface.php` | Injected ML-DSA signer for hybrid `signAlg` |
| `src/Http/HttpTransportInterface.php` | Pluggable HTTP transport for `send()`/`sendFile()` |
| `src/Http/CurlTransport.php` | Default cURL transport |
| `src/Http/Psr18Transport.php` | PSR-18 transport adapter |
| `src/Exceptions/SecurePayloadException.php` | HTTP-style errors (400/401/422/500) + `context` |
| `src/KMS/Kms.php` | Key-wrapping interface (`wrap`/`unwrap`) |
| `src/KMS/LocalKms.php` | XChaCha20 KEK wrapping from env |
| `src/KMS/VaultKms.php` | HashiCorp Vault Transit |
| `src/KMS/AwsKms.php` | AWS KMS EncryptionContext |
| `src/KMS/GcpKms.php` | GCP Cloud KMS additionalAuthenticatedData |
| `src/KMS/AzureKeyVaultKms.php` | Azure Key Vault Cryptography |
| `src/KMS/EnvKeyProvider.php` | Keys from `SECUREPAYLOAD_{CID}_{KID}_*` env vars |
| `src/KMS/DbKeyProvider.php` | PDO `secure_keys` table + optional KMS unwrap + lifecycle filter (`useKeyLifecycle`) |
| `src/KMS/KeyManager.php` | Generate keys, `rotateKey()` / `revokeKey()`, SQL export |
| `src/KMS/KeyStatus.php` | Lifecycle constants: `active`, `retiring`, `revoked` |
| `src/KMS/SecureKeyProvider.php` | Provider interface |
| `src/ReplayStore/Psr16ReplayStore.php` | PSR-16 → `replayStore` callable |
| `src/Observability/PrometheusSecurityExporter.php` | Prometheus counter dari `onSecurityEvent` |
| `src/Observability/OpenTelemetrySecurityExporter.php` | Span OpenTelemetry dari `onSecurityEvent` (opsional) |
| `src/Webhook/WebhookVerifier.php` | Helper verifikasi webhook (`verifyFromGlobals`) |
| `examples/` | Framework integration patterns (legacy reference) |
| `packages/node-sdk/` | Node/TS SDK + Express/Fastify middleware |
| `packages/go-sdk/` | Go SDK + Gin/Echo/Fiber middleware |
| `tests/Unit/` | Unit tests |
| `tests/Integration/` | Round-trip tests |
| `tests/Security/` | Security regression (spoofing, replay, downgrade, AAD) |
| `tests/Conformance/` | Protocol fixture vectors (`docs/fixtures/v3/`, `v4/`) |
| `docs/PROTOCOL.md` | Normative protocol spec (v3 + v4 appendix) |
| `docs/RFC9421_BRIDGE.md` | RFC 9421 interop |
| `docs/POST_QUANTUM.md` | Hybrid ML-DSA signing |
| `docs/fixtures/` | Portable test vectors + generator |

## Security Modes

| Mode | Signing | Encryption | Needs `ext-sodium` |
|------|---------|------------|-------------------|
| `hmac` | HMAC-SHA256 | — | No |
| `aead` | — (AEAD tag) | XChaCha20-Poly1305 | Yes |
| `both` | HMAC on **plaintext** | XChaCha20-Poly1305 | Yes |

`signAlg` mirror for request **and** response:
- `hmac` (default): HMAC-SHA256 with shared secret both directions
- `ed25519`: request = client keypair; response = **server** keypair (distinct keys)
- `hybrid-mldsa44-ed25519`: Ed25519 ‖ ML-DSA-44 via injected `pqSigner` (see `docs/POST_QUANTUM.md`)

| Purpose | Client holds | Server holds (keyLoader) |
|---------|-------------|--------------------------|
| Request sign (Ed25519) | `ed25519SecretKeyB64` | `ed25519PublicKeyB64` |
| Response verify (Ed25519) | `ed25519PublicKeyServerB64` | — |
| Response sign (Ed25519) | — | `ed25519SecretKeyServerB64` |
| Hybrid ML-DSA | `mldsa*` + `pqSigner` | `mldsaPublicKeyB64` (+ server keys for response) |

## Client Entry Points

| Method | Purpose |
|--------|---------|
| `buildHeadersAndBody($url, $method, $payload, $extraHeaders?)` | Core: headers + processed body |
| `send($url, $method, $payload, $extraHeaders?)` | HTTP via `httpTransport` or CurlTransport fallback |
| `buildFilePayload()` / `sendFile()` | In-memory file (base64 in JSON, ≤ ~10MB) |
| `buildFileStream()` | Large file: secretstream per-chunk + manifest |
| `buildFileStreamMultipartRequest()` | v4 multipart: SP-secured manifest + ciphertext parts |
| `verifyResponse()` / `verifyResponseOrThrow()` | Verify server response |
| `SecurePayload::deriveKey()` | Public HKDF helper |
| `SecurePayload::buildRequestAeadAad()` / `buildResponseAeadAad()` | Public AAD builders (conformance / cross-lang ports) |

## Server Entry Points

| Method | Purpose |
|--------|---------|
| `verify($headers, $rawBody, $method, $path, $query)` | Safe: returns `['ok'=>bool, ...]` |
| `verifyOrThrow(...)` | Throws `SecurePayloadException` |
| `verifySimple(...)` | Same without query arg |
| `verifyFilePayload(...)` | File attachment + constraints |
| `verifyFileStream($encPath, $manifest, $destPath, $constraints)` | Streaming decrypt + validate |
| `verifyFileStreamMultipart(...)` | v4: parse multipart → verify payload → decrypt stream |
| `buildResponse($requestHeaders, $payload)` | Signed/encrypted response |

Server loads keys via `keyLoader: fn(string $cid, string $kid): array`.

## Request Flow (Client → Server)

```
Client: buildHeadersAndBody()
  → parse URL → canonical path + query (ksort, rawurlencode)
  → generate timestamp + nonce
  → encrypt body (aead/both) with AAD (timestamp + bindHeaders)
  → sign plaintext (hmac/both) or Ed25519
  → attach X-* headers

Server: verify()
  → read clientId/keyId from headers
  → keyLoader(cid, kid) → hmacSecret, aeadKeyB64, ed25519PublicKeyB64
  → validate timestamp window
  → checkReplay(nonce) — key = hash(cid|kid|nonce), TTL = replayTtl + clockSkew
  → decrypt (aead/both) using method/path/query FROM SERVER INPUT
  → verify signature
  → return json + bodyPlain
```

## Security Headers (`HX_*` constants)

Request: `X-Client-Id`, `X-Key-Id`, `X-Timestamp`, `X-Nonce`, `X-Signature-*`, `X-Body-Digest`, `X-Canonical-Request` (debug only), `X-AEAD-*`.

Response: `X-Resp-*` namespace (timestamp, nonce, signature, body-digest, AEAD).

## Completed Phases (v2.7.0)

| Phase | Feature |
|-------|---------|
| 1 | Core HMAC/AEAD/BOTH + replay + KMS |
| 1b | Ed25519 request signing (v2.0) |
| 2 | Response two-way integrity |
| 3 | AAD binding (timestamp + `bindHeaders`) — wire v3 |
| 4 | `Psr16ReplayStore` |
| 5 | `deriveKeys` HKDF subkeys |
| 6 | `buildFileStream` / `verifyFileStream` |
| 7 | `VaultKms`, `AwsKms` |
| 15 | `GcpKms`, `AzureKeyVaultKms`, `PrometheusSecurityExporter` |
| 8 | `onSecurityEvent` observability |
| 9 | Ed25519 response signing (mirror `signAlg`) |
| 10 | Key rotation + grace period (`KeyManager::rotateKey`, `useKeyLifecycle`) |

## Key Rotation (Phase 10)

- Multiple `key_id` rows per `client_id`; client sends explicit `X-Key-Id`
- `DbKeyProvider` + `useKeyLifecycle=true`: load only `active` or `retiring` within `valid_until`
- `KeyManager::rotateKey()` → SQL UPDATE old key to `retiring`, INSERT new as `active`
- Response signing uses server keys from **same kid** as request — no wire change
- Procedure: `docs/KEY_ROTATION.md`

## Security Invariants (Never Break)

1. **Canonicalization symmetric** — `normalizePath()`, `canonicalQuery()`, `hmacMessage()`, `aeadNonceFrom()` must match client and server.
2. **Server derives method/path/query from its own request input** — NOT from `X-Canonical-Request`. See `tests/Security/SignatureSpoofingTest.php`.
3. **HMAC signs plaintext** in `both` mode, not ciphertext.
4. **AEAD nonce** derived from client nonce bound to method/path/query; verified with `hash_equals`.
5. **Replay key** = `hash(clientId|keyId|nonce)` — excludes timestamp. Remembered for `replayTtl + clockSkew`.
6. **`hash_equals`** for all secret/signature comparisons.
7. **HMAC secret** ≥ 32 chars; **AEAD key** exactly 32 bytes decoded.
8. **`signAlg` determined by server config**, not client header (anti-downgrade).
9. **`deriveKeys` and `bindHeaders` must match** on client and server.
10. **Response bound to request nonce** — cannot relocate to another request context.

## Extension Points

- `keyLoader` — per-(clientId, keyId) secrets
- `replayStore` — `fn(string $key, int $ttl): bool` (true = new nonce)
- `bindHeaders` — critical headers in AEAD AAD
- `deriveKeys` — HKDF domain separation
- `onSecurityEvent` — SIEM/rate-limit hook (no secrets in context)
- `Kms` interface — wrap/unwrap AEAD keys at rest

## Exploring the Codebase

Use GitNexus MCP with `repo: "SecurePayload"`:
- `query({query: "verify replay decrypt", repo: "SecurePayload"})`
- `context({name: "verify", repo: "SecurePayload"})`
- `impact({target: "checkReplay", direction: "upstream", repo: "SecurePayload"})`

## Further Reading

- User docs: `README.md`
- Roadmap: `docs/ROADMAP.md`
- Examples: `examples/EXAMPLES.md`
- Maintainer guide: `CLAUDE.md`
