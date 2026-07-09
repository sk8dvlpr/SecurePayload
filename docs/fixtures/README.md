# SecurePayload Protocol Fixtures

Machine-readable test vectors for **protocol version 3**. Used by `tests/Conformance/` and intended for porting to Node.js / Go (Phase 14).

## Layout

```
docs/fixtures/
  schema.json          # JSON Schema (informal)
  README.md            # this file
  v3/
    keys/standard.json # shared conformance keys
    primitive/         # byte-exact primitive outputs
    wire/              # full request (+ optional response) vectors
    negative/          # tampered requests that MUST fail verify
```

## Regenerating Fixtures

From the repository root (requires `ext-sodium` for Ed25519 vectors):

```bash
php tools/generate-protocol-fixtures.php
```

The generator uses fixed clock/nonce injectors (`clock`, `nonceGenerator`, `respNonceGenerator`) so output is deterministic.

## Running Conformance Tests

```bash
composer test -- --testsuite Conformance
# or
vendor/bin/phpunit --testsuite Conformance
```

## Fixture Types

| Directory | Purpose |
|-----------|---------|
| `primitive/` | Single-step functions: `normalizePath`, `canonicalQuery`, `hmacMessage`, AEAD nonce/AAD, HKDF, response helpers |
| `wire/` | Client build output (`expected.headers` + `expected.body`); roundtrip fixtures include `expected.response` |
| `negative/` | Same shape as wire, but verification must return `ok=false` (bad signature, nonce, timestamp, signAlg downgrade) |

## Shared Keys (`v3/keys/standard.json`)

| Field | Value (fixture) |
|-------|-----------------|
| `clientId` | `conf-client` |
| `keyId` | `conf-key-v1` |
| `hmacSecret` | 64-char hex string (32 bytes when used as raw secret) |
| `aeadKeyB64` | base64 of 32× `0x11` |
| Ed25519 | Deterministic keypairs from 32-byte seeds `0x42` (client) and `0x43` (server) |

Fixed timestamps/nonces (all wire fixtures):

- `timestamp`: `1700000000`
- `nonce_b64`: `AQEBAQEBAQEBAQEBAQEBAQ==` (16× `0x01`)
- `resp_timestamp`: `1700000060`
- `resp_nonce_b64`: `AgICAgICAgICAgICAgICAg==` (16× `0x02`)

## Porting to Other Languages

1. Implement primitives per `docs/PROTOCOL.md`.
2. Load `keys/standard.json` and each `wire/*.json`.
3. Rebuild headers/body from `request` + `config` + `fixed` + keys.
4. Assert byte-exact match with `expected`.
5. Run server verify; for roundtrip fixtures, build/verify response too.
6. Assert all `negative/*.json` fail verification.

Reference implementation: `src/SecurePayload.php` static helpers (`normalizePath`, `hmacMessage`, `buildRequestAeadAad`, etc.).
