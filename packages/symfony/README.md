# sk8dvlpr/securepayload-symfony

Symfony bundle for [sk8dvlpr/securepayload](https://github.com/sk8dvlpr/SecurePayload).

## Install

```bash
composer require sk8dvlpr/securepayload-symfony
```

Register `SecurePayload\Symfony\SecurePayloadBundle` in `config/bundles.php` and import `config/packages/securepayload.yaml` (copy from package `config/securepayload.yaml`).

## Services

- `securepayload.server` — verify incoming requests
- `SecurePayload\Symfony\Service\SecurePayloadClient` — outgoing signed requests

Verified result on request attribute `securepayload`.
