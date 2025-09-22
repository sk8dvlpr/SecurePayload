# SecurePayload

> Library PHP (Composer) untuk **keamanan request**: `HMAC-SHA256`, `AEAD XChaCha20-Poly1305`, atau **BOTH** (encrypt + sign) — semua dalam **satu class**.

[![CI](https://img.shields.io/github/actions/workflow/status/sk8dvlpr/securepayload/ci.yml?label=CI)]()
[![PHP](https://img.shields.io/badge/PHP-%E2%89%A5%208.0-blue)]()
[![License: MIT]
[![Packagist Version](https://img.shields.io/packagist/v/sk8dvlpr/securepayload.svg)](https://packagist.org/packages/sk8dvlpr/securepayload)
[![Packagist Downloads](https://img.shields.io/packagist/dt/sk8dvlpr/securepayload.svg)](https://packagist.org/packages/sk8dvlpr/securepayload)(https://img.shields.io/badge/License-MIT-green.svg)]()

- **Satu class** `SecurePayload\SecurePayload` yang menyatukan **client** & **server** use‑case.
- **Anti‑replay** (TTL), cek **timestamp** + **nonce**, canonical signing, error handling jelas.
- **Sumber key fleksibel**: ENV (`EnvKeyProvider`) atau DB (`DbKeyProvider`) + opsional `LocalKms` untuk unwrap AEAD key yang disimpan terenkripsi di DB.
- Framework-agnostic (CI4/Laravel/Symfony/Slim/dll).

---

## Instalasi
```bash
composer require sk8dvlpr/securepayload
```
> Butuh `ext-sodium` untuk mode AEAD/BOTH, dan `ext-curl` jika pakai helper `send()`.

---

## Quickstart

### Client: buat header & body
```php
use SecurePayload\SecurePayload;

$sp = new SecurePayload([
  'mode'         => 'both',      // 'hmac' | 'aead' | 'both'
  'version'      => '1',
  'clientId'     => 'my-client',
  'keyId'        => 'k1',
  'hmacSecretRaw'=> 'raw-hmac-secret',               // dibutuhkan saat HMAC/BOTH
  'aeadKeyB64'   => base64_encode(random_bytes(32)), // dibutuhkan saat AEAD/BOTH
]);

[$headers, $body] = $sp->buildHeadersAndBody(
  'https://api.example.com/foo?x=1', 'POST', ['hello'=>'world']
);
```

### Server: verifikasi (tanpa exception)
```php
use SecurePayload\SecurePayload;
use SecurePayload\KMS\EnvKeyProvider;

$provider  = new EnvKeyProvider();
$keyLoader = fn($cid,$kid) => $provider->load($cid,$kid);

$sp = new SecurePayload(['mode'=>'both','version'=>'1','keyLoader'=>$keyLoader]);

$vr = $sp->verify($headers, $rawBody, $method, $path, $query);
if (!$vr['ok']) {
  http_response_code($vr['status'] ?? 400);
  echo json_encode(['error'=>$vr['error']]); exit;
}
$data = $vr['json']; // payload terverifikasi & (jika BOTH/AEAD) sudah didekripsi
```

### Server (alternatif): verifikasi (dengan exception)
```php
try {
  $result = $sp->verifyOrThrow($headers, $rawBody, $method, $path, $query);
} catch (SecurePayload\Exceptions\SecurePayloadException $e) {
  http_response_code($e->getCode() ?: 400);
  echo json_encode(['error'=>$e->getMessage(), 'debug'=>$e->getContext()]); exit;
}
```

---

## Sumber Key

### Opsi A — ENV
Variabel (scoped per client+key):
- `SECUREPAYLOAD_{CLIENTID}_{KEYID}_HMAC_SECRET`
- `SECUREPAYLOAD_{CLIENTID}_{KEYID}_AEAD_KEY_B64`

Fallback global (opsional):
- `SECURE_HMAC_SECRET`
- `SECURE_AEAD_KEY_B64`

**Contoh**
```php
use SecurePayload\KMS\EnvKeyProvider;
$provider  = new EnvKeyProvider();
$keyLoader = fn($cid,$kid) => $provider->load($cid,$kid);
```

### Opsi B — DB (multi‑client)
Tabel default `secure_keys`:
- `client_id` (VARCHAR)
- `key_id` (VARCHAR)
- `hmac_secret` (TEXT; RAW string **bukan** base64)
- `aead_key_b64` (TEXT; base64 32‑byte) **atau** `wrapped_b64` + `kek_id` (jika pakai KMS)

```php
use PDO;
use SecurePayload\KMS\DbKeyProvider;
use SecurePayload\KMS\LocalKms;

$pdo = new PDO('mysql:host=localhost;dbname=app;charset=utf8mb4','user','pass');
$kms = LocalKms::fromEnv(); // jika pakai wrapped_b64

$provider  = new DbKeyProvider($pdo, [], $kms); // skema default
$keyLoader = fn($cid,$kid) => $provider->load($cid,$kid);
```

**Skema MySQL contoh**
```sql
CREATE TABLE secure_keys (
  client_id    VARCHAR(128) NOT NULL,
  key_id       VARCHAR(128) NOT NULL,
  hmac_secret  TEXT NULL,
  aead_key_b64 TEXT NULL,
  wrapped_b64  TEXT NULL,
  kek_id       VARCHAR(64) NULL,
  PRIMARY KEY (client_id, key_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

---

## Generate KEK (untuk LocalKms)
Pilih salah satu:
```bash
openssl rand -base64 32
# atau
php -r "echo base64_encode(random_bytes(32)), PHP_EOL;"
```
Set ENV:
```
SECURE_KEKS=kek1
SECURE_KEK_kek1_B64=<base64 32-byte di atas>
```

---

## Membungkus AEAD key ke DB (wrapped_b64)
```php
use SecurePayload\KMS\LocalKms;

$kms = LocalKms::fromEnv();
$rawKey32 = random_bytes(32);
$wrappedB64 = $kms->wrap('kek1', $rawKey32, ['purpose'=>'securepayload-aead-key']);
# Simpan $wrappedB64 & kek_id='kek1' ke kolom DB
```

---

## Examples
Contoh middleware siap pakai:
- **Laravel**: `examples/laravel/SecurePayloadMiddleware.php`
- **CodeIgniter 4**: `examples/ci4/SecurePayloadFilter.php`
- **Slim (PSR-15)**: `examples/slim/SecurePayloadMiddleware.php`
- **Symfony**: `examples/symfony/SecurePayloadSubscriber.php`
- **Lumen**: `examples/lumen/SecurePayloadMiddleware.php`
