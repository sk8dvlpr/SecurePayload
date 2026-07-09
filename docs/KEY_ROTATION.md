# Key Rotation — Prosedur Operasional

Panduan rotasi kunci SecurePayload tanpa downtime client–server. Fitur ini **tidak mengubah wire protocol** — client tetap mengirim `X-Key-Id` eksplisit; server memuat kunci exact match selama masih dalam status `active` atau `retiring` (grace window).

## Prasyarat

- `DbKeyProvider` dengan tabel `secure_keys` (composite PK: `client_id` + `key_id`)
- Backup database sebelum rotasi
- Kolom lifecycle (jalankan migrasi):

```bash
# Lihat docs/migrations/001_key_lifecycle.sql
```

- Aktifkan filter lifecycle di server:

```php
$provider = new DbKeyProvider($pdo, [
    'useKeyLifecycle' => true,
]);
$keyLoader = fn (string $cid, string $kid): array => $provider->load($cid, $kid);
```

## Alur Rotasi Standar

### 1. Generate kunci baru + SQL migrasi

```php
use SecurePayload\KMS\KeyManager;

$km = new KeyManager($kms); // $kms opsional untuk wrap AEAD
$result = $km->rotateKey(
    clientId: 'partner1',
    currentKeyId: 'key_v1',
    newKeyId: 'key_v2',           // opsional; default key_v1_rot_{YmdHis}
    graceSeconds: 86400,          // 24 jam overlap
    kekId: 'prod-kek-1',          // wajib jika KeyManager pakai KMS
    includeEd25519Client: false,  // true jika signAlg=ed25519
    includeEd25519Server: false   // true jika response Ed25519
);

echo $result->toSqlUpdateRetiring(); // UPDATE key_v1 → retiring + valid_until
echo $result->toSqlInsertNew();      // INSERT key_v2 → active

// Distribusi ke client (JANGAN simpan secret di server):
// - hmacSecret: $result->newKey->hmacSecret
// - aeadKeyB64: $result->newKey->aeadKeyB64
// - ed25519SecretKeyB64: $result->ed25519SecretKeyB64 (jika ada)
// - ed25519PublicKeyServerB64: $result->newKey->ed25519ServerPublicB64 (client verify response)
```

### 2. Jalankan SQL di database

Jalankan kedua statement dalam urutan: **UPDATE retiring dulu**, lalu **INSERT active**.

### 3. Rollout client bertahap

- Client lama: tetap pakai `keyId=key_v1` + kredensial lama → valid selama grace
- Client baru: update ke `keyId=key_v2` + kredensial baru
- Tidak perlu deploy server dan client secara simultan

### 4. Monitor

- Pantau `EVENT_KEY_NOT_FOUND` / HTTP 401 setelah grace berakhir
- Spike 401 pada `key_v1` = client belum migrasi; perpanjang grace atau hubungi partner

### 5. Cleanup setelah grace

```php
// Revoke manual (segera):
echo $km->revokeKey('partner1', 'key_v1');

// Atau cron: tandai retiring expired sebagai revoked
echo $km->purgeExpiredRetiringKeys('secure_keys');
```

## Status Lifecycle

| Status | `valid_until` | Server load |
|--------|---------------|-------------|
| `active` | NULL | OK |
| `retiring` | unix timestamp | OK jika `now <= valid_until` |
| `revoked` | NULL | Ditolak (null keys) |

Tanpa `useKeyLifecycle=true`, semua row dianggap aktif selamanya (backward compatible).

## Rotasi Env-only (Tanpa DB)

Untuk setup `EnvKeyProvider`:

1. Tambah env var baru: `SECUREPAYLOAD_{CID}_{KEY_V2}_HMAC_SECRET`, dll.
2. Deploy env + restart server
3. Update client ke `keyId=KEY_V2`
4. Hapus env `KEY_V1` setelah semua client migrasi

Tidak ada grace otomatis — overlap = periode di mana kedua env var masih ada.

## Ed25519 (`signAlg=ed25519`)

Saat rotasi dengan Ed25519:

- **Client** dapat: `ed25519SecretKeyB64` (request signing) + `ed25519PublicKeyServerB64` (response verify)
- **Server DB** simpan: `ed25519_public_b64` (verify request) + `ed25519_server_secret_b64` / `ed25519_server_public_b64` (sign response)
- Aktifkan `useEd25519` + `useEd25519Server` di `DbKeyProvider`

## Invariant Keamanan

- Server **tidak** mencoba multiple `keyId` otomatis saat verifikasi gagal
- Response signing memakai kunci server dari **kid yang sama** dengan request
- Replay nonce cache per `(clientId, keyId, nonce)` — rotasi tidak membagikan nonce antar keyId

## Referensi API

| Class / Method | Peran |
|----------------|-------|
| `KeyManager::rotateKey()` | Generate kunci baru + SQL |
| `KeyManager::revokeKey()` | Revoke segera |
| `KeyManager::purgeExpiredRetiringKeys()` | Cron cleanup |
| `KeyRotationResult::toSqlUpdateRetiring()` | SQL UPDATE key lama |
| `KeyRotationResult::toSqlInsertNew()` | SQL INSERT key baru |
| `DbKeyProvider` + `useKeyLifecycle` | Filter active/retiring/revoked |
| `KeyStatus::ACTIVE / RETIRING / REVOKED` | Konstanta status |
