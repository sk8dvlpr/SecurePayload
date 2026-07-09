---
name: securepayload-integration
description: Guides integrating SecurePayload into applications and frameworks — middleware, replay stores, KMS, client services. Use when writing or updating examples/, framework middleware, replay-store setup, or production deployment patterns.
---

# SecurePayload — Integration Guide

## Client vs Server Setup

**Client** requires: `clientId`, `keyId`, and key material (`hmacSecretRaw` and/or `aeadKeyB64` and/or `ed25519SecretKeyB64`).

**Server** requires: `keyLoader` callable — no client keys in constructor.

Both sides must match: `mode`, `version`, `signAlg`, `deriveKeys`, `bindHeaders`.

## Minimal Client

```php
$client = new SecurePayload([
    'mode' => 'both',
    'clientId' => 'client_001',
    'keyId' => 'key_v1',
    'hmacSecretRaw' => $hmacSecret,  // ≥ 32 chars
    'aeadKeyB64' => $aeadKeyB64,     // 32 bytes base64
]);
[$headers, $body] = $client->buildHeadersAndBody($url, 'POST', $payload);
// Send via Guzzle, Laravel Http, Symfony HttpClient, cURL, etc.
```

## Minimal Server

```php
$server = new SecurePayload([
    'mode' => 'both',
    'keyLoader' => fn($cid, $kid) => $provider->load($cid, $kid),
]);
$result = $server->verify(
    $headers,
    $rawBody,
    $requestMethod,   // from framework/server — NOT from header
    $requestPath,
    $queryParams
);
```

## Key Providers

### EnvKeyProvider (dev/single-tenant)

```
SECUREPAYLOAD_{CID}_{KID}_HMAC_SECRET
SECUREPAYLOAD_{CID}_{KID}_AEAD_KEY_B64
SECUREPAYLOAD_{CID}_{KID}_ED25519_PUBLIC_B64
SECUREPAYLOAD_{CID}_{KID}_ED25519_SERVER_SECRET_B64
SECUREPAYLOAD_{CID}_{KID}_ED25519_SERVER_PUBLIC_B64
```

### DbKeyProvider (multi-client production)

```php
$provider = new DbKeyProvider($pdo, [], LocalKms::fromEnv());
// Wrapped AEAD: wrapped_b64 + kek_id → auto unwrap via Kms
// Ed25519 client (request): opts['useEd25519'] => true
// Ed25519 server (response): opts['useEd25519Server'] => true
```

### Key generation

```php
$manager = new KeyManager($kms);
$result = $manager->generateKeyPair('client_002', 'key_v1', 'kek_id');
$serverPair = $manager->generateEd25519ServerKeyPair();
// $serverPair['secretB64'] → server DB; $serverPair['publicB64'] → give to client
```

## Replay Store (Multi-Server Production)

**Default file cache is NOT shared across servers.** Inject `replayStore`:

### Redis (recommended — atomic)

See `examples/replay-store/redis.php`:
```php
'replayStore' => fn(string $key, int $ttl) use ($redis): bool =>
    (bool) $redis->set($key, '1', ['nx', 'ex' => $ttl]),
```

### Memcached

`examples/replay-store/memcached.php` — `add()` atomic.

### PSR-16

```php
use SecurePayload\ReplayStore\Psr16ReplayStore;
'replayStore' => new Psr16ReplayStore($cache),
```

Check `isAtomic()` — non-atomic caches have race window under high concurrency.

## Framework Packages (Phase 12 — preferred)

| Framework | Package | Install |
|-----------|---------|---------|
| Laravel | `sk8dvlpr/securepayload-laravel` | `composer require sk8dvlpr/securepayload-laravel` |
| Symfony | `sk8dvlpr/securepayload-symfony` | `composer require sk8dvlpr/securepayload-symfony` |
| CI4 | `sk8dvlpr/securepayload-ci4` | `composer require sk8dvlpr/securepayload-ci4` |
| Slim | `sk8dvlpr/securepayload-slim` | `composer require sk8dvlpr/securepayload-slim` |

Monorepo path: `packages/{laravel,symfony,ci4,slim}/`. Each ships `SecurePayloadFactory`, server middleware/filter/subscriber, and client service. Laravel adds `securepayload:generate-keys` and `securepayload:rotate-key` Artisan commands.

**Lumen:** use `securepayload-laravel` with manual bootstrap (no auto-discovery).

## HTTP Transport (Phase 13)

| Transport | Use |
|-----------|-----|
| `CurlTransport` | Default fallback when `ext-curl` available |
| `Psr18Transport` | Inject PSR-18 `ClientInterface` + factories |
| Custom | Implement `HttpTransportInterface`, pass as `httpTransport` opt |

```php
use SecurePayload\Http\Psr18Transport;

$client = new SecurePayload([
    // ...keys...
    'httpTransport' => new Psr18Transport($httpClient, $requestFactory, $streamFactory),
]);
```

## CLI (`sk8dvlpr/securepayload-cli`)

```bash
composer global require sk8dvlpr/securepayload-cli
securepayload keys:generate client-a key-v1
securepayload keys:rotate client-a key-v1 --grace=86400
securepayload debug:verify -H headers.json -b @body.json --method=POST --path=/v1/pay
securepayload test:roundtrip --mode=both
```

Package path: `packages/cli/`.

## Framework Examples (legacy reference)

| Framework | Server | Client |
|-----------|--------|--------|
| Laravel | `examples/laravel/SecurePayloadMiddleware.php` | `SecurePayloadService.php` |
| Lumen | `examples/lumen/SecurePayloadMiddleware.php` | `SecurePayloadService.php` |
| CI4 | `examples/ci4/SecurePayloadFilter.php` | `SecurePayloadClient.php` |
| Symfony | `examples/symfony/SecurePayloadSubscriber.php` | `SecurePayloadService.php` |
| Slim | `examples/slim/SecurePayloadMiddleware.php` | `SecurePayloadClient.php` |
| Native | `examples/native/index.php` | `sender.php` |

Full index: `examples/EXAMPLES.md` (deprecation notice → use packages above).

## Middleware Pattern

1. Normalize headers to uppercase keys (library convention).
2. Call `verify()` with `$request->getMethod()`, path, query from framework.
3. On failure: return JSON error with `$result['status']`.
4. On success: attach `$result` to request attributes for controller.

**Never** pass method/path from `X-Canonical-Request`.

## Response Two-Way

Response signing **mirrors `signAlg`**:
- `signAlg=hmac`: shared HMAC secret (client `hmacSecretRaw`, server `keyLoader` `hmacSecret`)
- `signAlg=ed25519`: server signs with `ed25519SecretKeyServerB64`; client verifies with `ed25519PublicKeyServerB64` (no HMAC needed for response)

Server after successful verify:
```php
[$respHeaders, $respBody] = $server->buildResponse($reqHeaders, $data);
```

Client (`signAlg=ed25519` example):
```php
$client = new SecurePayload([
    'mode' => 'both',
    'signAlg' => 'ed25519',
    'clientId' => 'c1',
    'keyId' => 'k1',
    'ed25519SecretKeyB64' => $clientSecretB64,
    'ed25519PublicKeyServerB64' => $serverPublicB64,
    'aeadKeyB64' => $aeadKeyB64,
]);
[$reqHeaders, $reqBody] = $client->buildHeadersAndBody($url, 'POST', $payload);
$reqNonce = $reqHeaders[SecurePayload::HX_NONCE];
$res = $client->verifyResponse($responseHeaders, $responseBody, $reqNonce);
```

## File Upload

**Small files:** `buildFilePayload` / `verifyFilePayload` (in-memory base64).

**Large files:** `buildFileStream` → send manifest via secure request + upload ciphertext separately → `verifyFileStream`.

See `examples/file-stream/` and `examples/native/upload_*.php`.

## bindHeaders + extraHeaders

If using `bindHeaders => ['X-Request-Id']`:
```php
[$headers, $body] = $client->buildHeadersAndBody($url, 'POST', $payload, [
    'X-Request-Id' => $id,
]);
```
Same header names and values must reach server unchanged.

## Observability

```php
'onSecurityEvent' => function (string $event, array $context): void {
    // EVENT_REPLAY_DETECTED, EVENT_SIGNATURE_INVALID, etc.
    // No secrets in $context — safe for SIEM
},
```

## Production Checklist

```
- [ ] HTTPS on all endpoints
- [ ] mode, version, signAlg, deriveKeys, bindHeaders match both sides
- [ ] replayStore: Redis/Memcached (not file default) if >1 server
- [ ] DbKeyProvider + KMS wrap for AEAD keys at rest
- [ ] Key rotation: `useKeyLifecycle=true`, `KeyManager::rotateKey()` — see `docs/KEY_ROTATION.md`
- [ ] HMAC secrets ≥ 32 chars; rotate via new `keyId` + grace window
- [ ] onSecurityEvent → `PrometheusSecurityExporter` atau logging/SIEM
- [ ] Security test suite passes in CI
```

## Cloud KMS for Key Wrapping

```php
// Vault Transit (derived=true on key)
$kms = new VaultKms('https://vault:8200', $token);

// AWS KMS
$kms = new AwsKms($kmsClient);

// GCP Cloud KMS
$kms = new GcpKms($kmsClient);

// Azure Key Vault
$kms = new AzureKeyVaultKms($cryptoClient);

$provider = new DbKeyProvider($pdo, ['useKeyLifecycle' => true], $kms);
```

## Prometheus Metrics (Phase 15)

```php
use SecurePayload\Observability\PrometheusSecurityExporter;

$exporter = new PrometheusSecurityExporter();
$server = new SecurePayload([
    'mode' => 'both',
    'keyLoader' => $loader,
    'onSecurityEvent' => $exporter->onSecurityEvent(),
]);
// Endpoint /metrics: echo $exporter->render();
// Contoh lengkap: examples/observability/prometheus.php
```

## Future: Official Framework Packages

Phase 12 will publish Composer packages — until then, copy from `examples/` or wrap in app service provider.
