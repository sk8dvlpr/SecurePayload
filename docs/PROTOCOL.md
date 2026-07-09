# SecurePayload Protocol Specification (Version 3)

Normative reference for interoperable implementations. The PHP reference library is `sk8dvlpr/securepayload` (`SecurePayload::DEFAULT_VERSION = '3'`).

**Conformance:** JSON test vectors in `docs/fixtures/v3/`; validated by `tests/Conformance/`.

---

## 1. Overview

SecurePayload secures HTTP request/response bodies between a **client** and **server** using:

| Layer | Algorithms |
|-------|------------|
| Signing (request) | HMAC-SHA256 or Ed25519 |
| Signing (response) | HMAC-SHA256 or Ed25519 (server keypair when Ed25519) |
| Encryption | XChaCha20-Poly1305 IETF (`sodium_crypto_aead_xchacha20poly1305_ietf_*`) |
| Key derivation (opt-in) | HKDF-SHA256 |
| Anti-replay | Single-use nonce + timestamp window |

### 1.1 Security Modes

| Mode | Encrypt body | Sign body |
|------|--------------|-----------|
| `hmac` | No | Yes (plaintext JSON) |
| `aead` | Yes | No (AEAD tag only) |
| `both` | Yes | Yes (**plaintext** JSON, not ciphertext) |

### 1.2 Signing Algorithm (`signAlg`)

Configured on **server**; client must match for requests. Server **must not** accept a weaker algorithm than configured (anti-downgrade).

| `signAlg` | Request signer | Response signer | Header value |
|-----------|----------------|-----------------|--------------|
| `hmac` (default) | HMAC-SHA256 with shared secret | HMAC-SHA256 with shared secret | `HMAC-SHA256` |
| `ed25519` | Client Ed25519 secret key | Server Ed25519 secret key | `ED25519` |

Signatures are **base64-encoded** (standard alphabet, no padding required in transit but implementations accept padded forms).

---

## 2. HTTP Headers

### 2.1 Request Headers

| Header | Required | Description |
|--------|----------|-------------|
| `X-Client-Id` | Always | Client identifier |
| `X-Key-Id` | Always | Key identifier (supports rotation) |
| `X-Timestamp` | Always | Unix seconds (decimal string) |
| `X-Nonce` | Always | 16 random bytes, base64 |
| `X-Signature-Version` | Always | Protocol version (`3`) |
| `X-Canonical-Request` | Always | Debug hint only (see §3.4) |
| `X-Signature-Algorithm` | `hmac` / `both` | `HMAC-SHA256` or `ED25519` |
| `X-Body-Digest` | `hmac` / `both` | `sha256=` + base64(SHA-256(body)) |
| `X-Signature` | `hmac` / `both` | Signature over canonical message (§5) |
| `X-AEAD-Algorithm` | `aead` / `both` | Must be `XCHACHA20-POLY1305-IETF` |
| `X-AEAD-Nonce` | `aead` / `both` | base64(24-byte derived nonce, §6) |

Header names are case-insensitive on the wire; implementations normalize to uppercase for lookup.

### 2.2 Response Headers

| Header | Required | Description |
|--------|----------|-------------|
| `X-Resp-Timestamp` | Always | Unix seconds |
| `X-Resp-Nonce` | Always | 16 random bytes, base64 |
| `X-Resp-Signature-Version` | Always | Protocol version |
| `X-Resp-Signature-Algorithm` | Signed modes | `HMAC-SHA256` or `ED25519` |
| `X-Resp-Body-Digest` | Signed modes | Digest of **plaintext** response JSON |
| `X-Resp-Signature` | Signed modes | Over response canonical message (§8) |
| `X-Resp-AEAD-Algorithm` | Encrypted responses | `XCHACHA20-POLY1305-IETF` |
| `X-Resp-AEAD-Nonce` | Encrypted responses | base64(24-byte derived nonce, §6.2) |

---

## 3. Canonicalization

All string operations use **UTF-8**. Line endings in canonical messages are **LF** (`\n`).

### 3.1 Path Normalization (`normalizePath`)

```
if path == "": return "/"
path = "/" + ltrim(path, "/")
if length(path) > 1: path = rtrim(path, "/")
return path
```

Examples: `"" → "/"`, `"v1/pay" → "/v1/pay"`, `"/v1/pay/" → "/v1/pay"`.

### 3.2 Query Canonicalization (`canonicalQuery`)

Given a map of query parameters:

1. Sort keys ascending (`ksort`, string order).
2. For each key `k`, value `v`:
   - If `v` is array: `v = implode(",", map(strval, v))`
   - Else: `v = (string) v`
   - Emit `rawurlencode(k) + "=" + rawurlencode(v)`
3. Join pairs with `&`. Empty map → `""`.

### 3.3 Method

HTTP method uppercased: `POST`, `GET`, etc.

### 3.4 `X-Canonical-Request` (non-authoritative)

```
base64( METHOD + "\n" + normalizePath(path) + "\n" + canonicalQuery(query) )
```

**Security rule:** The server **must** derive `method`, `path`, and `query` from the actual HTTP request (or explicit caller arguments). It **must not** trust `X-Canonical-Request` for verification. That header exists for debugging only.

---

## 4. Body Encoding

### 4.1 Plaintext JSON (`hmac` mode)

```json
{"field":"value"}
```

Encoding: `json_encode` with `JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES` (no extra whitespace).

### 4.2 AEAD wrapper (`aead` / `both` modes)

Wire body is JSON:

```json
{"__aead_b64":"<base64(ciphertext+tag)>"}
```

Outer JSON uses `JSON_UNESCAPED_SLASHES` only (no `JSON_UNESCAPED_UNICODE` on the wrapper).

Plaintext inside AEAD (before encryption):

- `aead` mode: payload JSON as in §4.1
- `both` mode: payload JSON as in §4.1 (signed **before** encryption)

### 4.3 Body Digest

For signing modes, digest covers the **plaintext JSON string** (not the AEAD wrapper):

```
bodyDigestB64 = base64( SHA-256( plaintext_utf8 ) )
X-Body-Digest = "sha256=" + bodyDigestB64
```

---

## 5. Request Signature (HMAC / Ed25519)

### 5.1 Canonical Message (`hmacMessage`)

Lines joined by `\n`; **final line is empty** (trailing newline):

```
v{version}
client={clientId}
key={keyId}
ts={timestamp}
nonce={nonce_b64}
m={METHOD}
p={normalizePath(path)}
q={canonicalQuery}
bd=sha256:{bodyDigestB64}

```

(`{bodyDigestB64}` is raw base64 digest bytes, without the `sha256=` prefix.)

### 5.2 HMAC-SHA256

When `deriveKeys` is enabled (§7), signing key:

```
signKey = HKDF-SHA256(hmacSecretRaw, info="sp-sign-req|v{version}", len=32)
```

Otherwise `signKey = hmacSecretRaw` (UTF-8 bytes of the secret string).

```
signature = base64( HMAC-SHA256(signKey, canonicalMessage) )
```

Minimum secret length: **32 characters**.

### 5.3 Ed25519 (request)

When `deriveKeys` is enabled, the 64-byte expanded secret key is derived via HKDF from the seed material (library-internal); fixtures use direct Ed25519 keys.

```
signature = base64( Ed25519_sign(clientSecretKey, canonicalMessage) )
```

Server verifies with client's public key. `X-Signature-Algorithm` must be `ED25519`.

---

## 6. AEAD (XChaCha20-Poly1305)

Algorithm identifier: `XCHACHA20-POLY1305-IETF`  
Nonce length: **24 bytes**  
Key length: **32 bytes**

### 6.1 Request Nonce Derivation (`aeadNonceFrom`)

```
seed = base64_decode(nonce_b64)  // 16 bytes; invalid → 16 zero bytes
msg = METHOD + "\n" + normalizePath(path) + "\n" + queryString + "\n" + seed
nonce24 = substr( SHA-256(msg), 0, 24 )
```

`X-AEAD-Nonce` = `base64(nonce24)`.

Server **must** recompute nonce and compare with `constant-time equals` to header value.

### 6.2 Response Nonce Derivation (`respAeadNonceFrom`)

```
seed = base64_decode(resp_nonce_b64)
msg = "response" + "\n" + req_nonce_b64 + "\n" + seed
nonce24 = substr( SHA-256(msg), 0, 24 )
```

### 6.3 Request AAD (`buildRequestAeadAad`)

Lines joined by `\n`:

```
v{version}
ts={timestamp}
```

For each bound header (§6.4), append in **sorted lowercase name** order:

```
h:{lowercase_name}={value}
```

Example with `bindHeaders: ["X-Request-Id"]` and value `abc`:

```
v3
ts=1700000000
h:x-request-id=abc
```

PHP reference: `SecurePayload::buildRequestAeadAad()`.

### 6.4 Header Binding (`bindHeaders`)

Optional list of header names configured identically on client and server. For AAD:

1. Normalize configured names to lowercase.
2. Read values from extra/request headers (missing → empty string).
3. Sort map by key ascending.

Client collects from `$extraHeaders` before merge; server from incoming request headers.

### 6.5 Response AAD (`buildResponseAeadAad`)

Single string (not multiline):

```
resp-v{version}|req={req_nonce_b64}|ts={resp_timestamp}
```

### 6.6 Encryption

```
ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext_utf8,
    aad_string,
    nonce24,
    aeadKey32
)
```

When `deriveKeys` is enabled:

```
aeadKey32 = HKDF-SHA256(aeadMasterRaw, info="sp-aead-req|v{version}", len=32)   // request
aeadKey32 = HKDF-SHA256(aeadMasterRaw, info="sp-aead-resp|v{version}", len=32)  // response
```

Master AEAD key: 32 bytes from base64 decode of configured key.

---

## 7. HKDF Subkey Derivation (`deriveKeys`)

Opt-in on both peers. Purposes (info string for `hash_hkdf('sha256', ...)`):

| Purpose constant | Info string |
|------------------|---------------|
| Request AEAD | `sp-aead-req\|v{version}` |
| Request sign | `sp-sign-req\|v{version}` |
| Response AEAD | `sp-aead-resp\|v{version}` |
| Response sign | `sp-sign-resp\|v{version}` |
| File stream | `sp-aead-stream\|v{version}` |

```
deriveKey(master, purpose, len=32) = HKDF-SHA256(master, length=len, info=purpose)
```

Mismatching `deriveKeys` or `version` causes verification/decryption failure (fail-closed).

---

## 8. Response Signature

### 8.1 Canonical Message (`respMessage`)

Trailing empty line required:

```
resp-v{version}
req-nonce={req_nonce_b64}
resp-ts={resp_timestamp}
resp-nonce={resp_nonce_b64}
bd=sha256:{bodyDigestB64}

```

Digest is over **plaintext response JSON** (before AEAD wrapper if encrypted).

### 8.2 HMAC / Ed25519

Same rules as request (§5), using response purposes when `deriveKeys` is on:

- HMAC: `sp-sign-resp|v{version}`
- Ed25519: server secret key signs; client verifies with `ed25519PublicKeyServerB64`

Response signing mirrors request `signAlg`.

---

## 9. Verification Order (Server Request)

1. Required headers present; `X-Signature-Version ==` configured version.
2. Timestamp within window: `[now - (replayTtl + clockSkew), now + clockSkew]` (defaults: 120s + 60s).
3. Replay check: nonce single-use per `(clientId, keyId)` — key **excludes timestamp**.
4. Load keys for `(clientId, keyId)`.
5. If mode requires AEAD: assert `X-AEAD-Algorithm`; decrypt; verify nonce binding.
6. If mode requires signature: rebuild canonical message; verify signature (`hash_equals` / Ed25519 verify).
7. For `both`: signature is over **decrypted plaintext**, not wire body.

**Anti-downgrade:** If server `signAlg=ed25519`, reject requests with `X-Signature-Algorithm: HMAC-SHA256`.

---

## 10. Replay Protection

Default: file-based nonce store (single host). Production multi-server: shared store (Redis, etc.).

Cache key:

```
hash("clientId|keyId|nonce_b64")
```

Retention: **`replayTtl + clockSkew`** (not `replayTtl` alone).

---

## 11. Key Material

| Material | Format | Constraint |
|----------|--------|------------|
| HMAC secret | string | ≥ 32 chars |
| AEAD key | base64 | decodes to exactly 32 bytes |
| Ed25519 client | 64-byte secret / 32-byte public, base64 | Request sign/verify |
| Ed25519 server | 64-byte secret / 32-byte public, base64 | Response sign/verify |

Client sends `X-Client-Id` + `X-Key-Id`; server resolves secrets via key store.

---

## 12. Version History (Appendix)

### Version 3 (current)

- AEAD AAD binds `timestamp` + optional `bindHeaders` (breaking vs v2).
- HKDF `deriveKeys` opt-in.
- Ed25519 request + response signing.
- Response encryption + two-way binding via `req-nonce`.

### Version 2

- Introduced response signing/encryption (`buildResponse` / `verifyResponse`).
- AAD did not include bound custom headers or timestamp in all paths.

### Version 1

- Initial HMAC / AEAD / BOTH request-only protocol.
- No response layer; no Ed25519; no HKDF.

Implementations **must** reject mismatched `X-Signature-Version` / `X-Resp-Signature-Version`.

---

## 13. References

| Resource | Path |
|----------|------|
| Test vectors | `docs/fixtures/v3/` |
| Generator | `tools/generate-protocol-fixtures.php` |
| PHP implementation | `src/SecurePayload.php` (facade); primitives in `src/Protocol/` |
| Conformance tests | `tests/Conformance/` |

Static helpers exposed for cross-language ports:

- `normalizePath`, `canonicalQuery`, `bodyDigestB64`
- `hmacMessage`, `respMessage`
- `aeadNonceFrom`, `respAeadNonceFrom`
- `buildRequestAeadAad`, `buildResponseAeadAad`
- `deriveKey`
