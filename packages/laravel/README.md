# sk8dvlpr/securepayload-laravel

Laravel integration for [sk8dvlpr/securepayload](https://github.com/sk8dvlpr/SecurePayload).

## Install

```bash
composer require sk8dvlpr/securepayload-laravel
php artisan vendor:publish --tag=securepayload-config
```

## Middleware

Register `SecurePayload\Laravel\Http\Middleware\VerifySecurePayload` on routes. Verified payload: `$request->attributes->get('securepayload')`.

## Client

Inject `SecurePayload\Laravel\Services\SecurePayloadClient` and call `post($uri, $payload)`.

## Artisan

```bash
php artisan securepayload:generate-keys client-a key-v1
php artisan securepayload:rotate-key client-a key-v1 --grace=86400
```

See [docs/PROTOCOL.md](../../docs/PROTOCOL.md) and [docs/KEY_ROTATION.md](../../docs/KEY_ROTATION.md).
