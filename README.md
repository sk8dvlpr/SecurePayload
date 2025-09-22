# SecurePayload

Library PHP (Composer) **native** untuk keamanan request: **HMAC-SHA256**, **AEAD XChaCha20-Poly1305**, atau **keduanya (BOTH)**—dalam **satu class**: `SecurePayload\SecurePayload`. Tidak bergantung framework (bisa dipakai di CI4/Laravel/Slim/dll).

## Fitur
- **Satu class** untuk **Client** & **Server**.
- **Mode**: `hmac`, `aead`, atau `both` (encrypt + sign).
- **Header & Body builder** (client) dan **verifier/decryptor** (server).
- **Anti-replay** + cek **timestamp** & **nonce**.
- **Sumber key fleksibel**: **ENV** atau **DB** (multi-client). Opsi KMS tersedia untuk unwrap AEAD key.
- **Framework-agnostic**.

## Instalasi
```bash
composer require sk8dvlpr/securepayload
```

## Client (Singkat)
```php
use SecurePayload\SecurePayload;

$sp = new SecurePayload([
  'mode'         => 'both',
  'version'      => '1',
  'clientId'     => 'my-client',
  'keyId'        => 'k1',
  'hmacSecretRaw'=> 'raw-hmac-secret',
  'aeadKeyB64'   => base64_encode(random_bytes(32)),
]);

[$headers, $body] = $sp->buildHeadersAndBody('https://api.example.com/foo?x=1', 'POST', ['hello'=>'world']);
$res = $sp->send('https://api.example.com/foo?x=1','POST',['hello'=>'world'],['Accept'=>'application/json']);
```

## Server (Verify)
```php
use SecurePayload\SecurePayload;

$keyLoader = function (string $clientId, string $keyId): array {
  return [
    'hmacSecret' => 'raw-hmac-secret',
    'aeadKeyB64' => base64_encode(random_bytes(32)),
  ];
};

$sp = new SecurePayload([
  'mode'      => 'both',
  'version'   => '1',
  'keyLoader' => $keyLoader,
]);
```

## Sumber Key

### A. ENV
Gunakan `SecurePayload\KMS\EnvKeyProvider` atau `keyLoader` sendiri.
- Scoped per client+key:
  - `SECUREPAYLOAD_{CLIENTID}_{KEYID}_HMAC_SECRET`
  - `SECUREPAYLOAD_{CLIENTID}_{KEYID}_AEAD_KEY_B64`
- Fallback global (opsional):
  - `SECURE_HMAC_SECRET`
  - `SECURE_AEAD_KEY_B64`

**Contoh:**
```php
use SecurePayload\KMS\EnvKeyProvider;
$provider  = new EnvKeyProvider();
$keyLoader = fn($cid,$kid) => $provider->load($cid,$kid);
```

### B. DB (Multi-Client)
Gunakan `SecurePayload\KMS\DbKeyProvider` (PDO). Tabel default `secure_keys` dengan kolom:
- `client_id` (VARCHAR)
- `key_id` (VARCHAR)
- `hmac_secret` (RAW string, **bukan** base64)
- `aead_key_b64` (TEXT; base64 32-byte key) **atau**
- `wrapped_b64` (TEXT; base64 nonce||ciphertext bila pakai KMS)
- `kek_id` (VARCHAR; id KEK untuk unwrap)

**Contoh:**
```php
use PDO;
use SecurePayload\KMS\DbKeyProvider;
$pdo = new PDO('mysql:host=localhost;dbname=app;charset=utf8mb4','user','pass');
$provider  = new DbKeyProvider($pdo);
$keyLoader = fn($cid,$kid) => $provider->load($cid,$kid);
```

## Generate KEK (untuk KMS Local)
KEK = key untuk **membungkus** (wrap) AEAD key di DB.

- **Dengan OpenSSL (shell):**
```bash
openssl rand -base64 32
```
- **Dengan PHP (CLI):**
```bash
php -r "echo base64_encode(random_bytes(32)), PHP_EOL;"
```

Set ENV:
```
SECURE_KEKS=kek1
SECURE_KEK_kek1_B64=<ISI_BASE64_DARI_32_BYTE_DI_ATAS>
```

Kemudian di kode:
```php
use SecurePayload\KMS\LocalKms;
$kms = LocalKms::fromEnv();
```

Contoh skema MySQL:
```sql
CREATE TABLE secure_keys (
  client_id    VARCHAR(128) NOT NULL,
  key_id       VARCHAR(128) NOT NULL,
  hmac_secret  TEXT NULL,          -- RAW (bukan base64)
  aead_key_b64 TEXT NULL,          -- base64 dari 32-byte key (jika tanpa KMS)
  wrapped_b64  TEXT NULL,          -- base64(nonce||ciphertext) (jika pakai KMS)
  kek_id       VARCHAR(64) NULL,   -- id KEK untuk unwrap
  PRIMARY KEY (client_id, key_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```