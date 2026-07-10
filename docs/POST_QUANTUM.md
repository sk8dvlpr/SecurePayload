# Post-Quantum Hybrid Signing (Phase 18d)

Opt-in `signAlg` value: `hybrid-mldsa44-ed25519`.

**Header algorithm name:** `HYBRID-MLDSA44-ED25519` (`SecurePayload::HYBRID_ALG`)

## Wire format

```
X-Signature = base64( ed25519_sig (64 bytes) || mldsa44_sig (2420 bytes) )
```

Total raw signature length: **2484** bytes before base64.

Ed25519 uses the same keypairs as `signAlg=ed25519` (client for request, server for response). ML-DSA keys are separate:

| Field | Role |
|-------|------|
| `mldsaSecretKeyB64` / `mldsaPublicKeyB64` | Client (request) |
| `mldsaSecretKeyServerB64` / `mldsaPublicKeyServerB64` | Server (response) |

## Injection

Real ML-DSA is **not** bundled. Inject `SecurePayload\Crypto\PqSignerInterface`:

```php
$sp = new SecurePayload([
    'mode' => 'hmac',
    'signAlg' => 'hybrid-mldsa44-ed25519',
    'pqSigner' => $yourLiboqsAdapter, // wajib
    'ed25519SecretKeyB64' => ...,
    'mldsaPublicKeyB64' => ...,
]);
```

Without `pqSigner`, construction throws.

## Security notes

- Server `signAlg` is authoritative (anti-downgrade), same as Ed25519.
- Test suite uses a **hash-based stub** (`FakeMldsa44Signer`) for format/length only — not real PQ security.
- Prefer a FIPS 204 / liboqs-backed implementation in production.

## Version

Shipped in library **3.1.0**. Compatible with protocol version 4 (default) or explicit `version => '3'`.
