# sk8dvlpr/securepayload-slim

Slim 4 integration for [sk8dvlpr/securepayload](https://github.com/sk8dvlpr/SecurePayload).

## Install

```bash
composer require sk8dvlpr/securepayload-slim
```

```php
$server = SecurePayload\Slim\SecurePayloadFactory::createServer(
    SecurePayload\Slim\SecurePayloadFactory::defaultConfig()
);
$app->add(new SecurePayload\Slim\Middleware\VerifySecurePayload(
    $server,
    $responseFactory
));
```

Request attribute: `securepayload`.

## Client

Wire `SecurePayload\Slim\SecurePayloadClient` with PSR-18 client + request/stream factories.
