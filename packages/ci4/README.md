# sk8dvlpr/securepayload-ci4

CodeIgniter 4 integration for [sk8dvlpr/securepayload](https://github.com/sk8dvlpr/SecurePayload).

## Install

```bash
composer require sk8dvlpr/securepayload-ci4
```

Copy `vendor/.../Config/SecurePayload.php` to `app/Config/SecurePayload.php` and register filter `SecurePayload\Ci4\Filters\VerifySecurePayload` in `app/Config/Filters.php`.

## Client

Use `SecurePayload\Ci4\Libraries\SecurePayloadClient` for outgoing requests.

Verified payload on `$request->securepayload` after filter passes.
