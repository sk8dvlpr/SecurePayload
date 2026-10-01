# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 3.2.x   | Yes (current: 3.2.1) |
| < 3.2   | Best-effort fixes for critical issues only |

## Reporting a vulnerability

Please report security issues privately — do **not** open a public GitHub issue for vulnerabilities.

Email or contact the maintainer via the Packagist package page for `sk8dvlpr/securepayload`. Include:

- Affected version / commit
- Description and impact
- Reproduction steps or PoC (private)

We aim to acknowledge within 72 hours and ship a fix or mitigation advisory as soon as practical.

## Security guarantees (library scope)

**Guaranteed (when configured correctly):**

- Request authentication / integrity (HMAC-SHA256, Ed25519, or hybrid PQ)
- Confidentiality in `aead` / `both` modes (XChaCha20-Poly1305)
- Anti-replay when a correct `replayStore` is used (or single-host file store)
- Response binding to the request nonce
- Streaming file transfer fail-closed on tag/digest failure

**Not guaranteed (integrator responsibility):**

- Full TLS / transport hardening beyond `CurlTransport` defaults
- Binding of HTTP status / Content-Type on responses (not in wire AAD/signature today)
- Business authorization / RBAC
- Cross-server replay without injecting `replayStore` (set `requireReplayStore => true` in multi-server)
- Filesystem path safety when writing verified filenames — always sanitize + use a dedicated storage root

## Production checklist

1. Prefer `mode => 'both'` or at least AEAD for sensitive bodies
2. Inject Redis/Memcached (or PSR-16 with atomic `add()`) as `replayStore`; set `requireReplayStore => true`
3. Never trust `X-Canonical-Request`; pass server-derived method/path/query
4. Keep `signAlg` identical on client and server (anti-downgrade)
5. Use `CurlTransport` with HTTPS; set `requireHttps: true` for production clients
6. Rotate keys via `KeyManager::rotateKey()`; revoke promptly
7. Do not log `onSecurityEvent` contexts as if they were audit-complete — they omit secrets by design but may include digests/ids

## Known design notes

- Replay nonce is committed **after** successful authentication (auth-then-commit)
- Default file replay store is single-host only and fail-closed on I/O errors
- `EnvKeyProvider` accepts only `[A-Za-z0-9_]` client/key ids (no `-` / `.` collision)