# Key Lifecycle — Rotasi, Status Kunci, Destroy, dan Dekripsi Arsip

Panduan menyeluruh siklus hidup kunci SecurePayload: prosedur rotasi tanpa downtime (`KeyManager`), lapisan status siklus hidup (`active` → `retiring` → `revoked`/`destroyed`), penjadwalan penghancuran (*crypto-shredding*), dan "key ring" untuk membuka kembali arsip payload terenkripsi dengan **kunci yang tercatat di baris arsip** — bukan kunci aktif hari ini.

## Pola Status Lifecycle

| Status | Arti | Server load (`useKeyLifecycle=true`) | Dekripsi arsip |
|--------|------|--------------------------------------|----------------|
| `active` | Kunci produksi saat ini | OK | OK |
| `retiring` | Masih valid sampai `valid_until` (grace) | OK selama `now <= valid_until` | OK selama grace belum habis |
| `revoked` | Ditolak segera, tanpa grace | Ditolak (null keys) | DITOLAK (401) |
| `destroyed` | Telah dihancurkan; tak dapat dipulihkan | Ditolak | DITOLAK PERMANEN (`KeyDestroyedException`, 410) |

Status kosong/NULL di DB dinormalisasi ke `active` (backward compatible). Rotasi via CLI existing — `securepayload keys:rotate <cid> <kid> --grace=86400` — menghasilkan pasangan status ini juga (key lama jadi `retiring` + `valid_until`); `KeyLifecycleManager` adalah operasi lanjutannya: revoke manual, jadwal destroy, dan dekripsi arsip.

## Persiapan Skema

```bash
# 1. Kolom lifecycle dasar (wajib untuk retire/revoke):
#    docs/migrations/001_key_lifecycle.sql
#    ALTER TABLE secure_keys ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'active';
#    ALTER TABLE secure_keys ADD COLUMN valid_until INTEGER NULL;

# 2. Kolom jadwal destroy (OPSIONAL — hanya bila fitur destroy diaktifkan):
#    docs/migrations/002_key_destroy.sql
#    ALTER TABLE secure_keys ADD COLUMN destroy_after INTEGER NULL;   -- MySQL: BIGINT NULL
```

## Instansiasi

```php
use SecurePayload\KMS\KeyLifecycleManager;
use SecurePayload\KMS\LocalKms;

$klm = new KeyLifecycleManager($pdo, [
    'table'           => 'secure_keys',   // nama tabel/kolom mirror DbKeyProvider
    'colStatus'       => 'status',
    'colValidUntil'   => 'valid_until',
    // Fitur destroy (butuh kolom destroy_after dari migrasi 002):
    'useDestroyAfter' => true,
    // WAJIB SAMA dengan config saat payload asli diverifikasi (lihat decryptArchivedLog):
    'deriveKeys'      => false,
    'version'         => '4',
    'bindHeaders'     => [],
], LocalKms::fromEnv());                  // KMS wajib hanya bila baris kunci memakai wrapped key
```

## Operasi Transisi Status

```php
// Retire dengan grace period (setelahnya server menolak key lama):
$klm->retire('partner1', 'key_v1', 86400);

// Revoke segera — tanpa grace, tanpa syarat status lain:
$klm->revoke('partner1', 'key_v2');

// Jadwalkan penghancuran (status TIDAK berubah; butuh useDestroyAfter=true):
$klm->scheduleDestroy('partner1', 'key_v3', strtotime('+90 days'));

// Cron: eksekusi destroy yang sudah jatuh tempo. Return true = dieksekusi sekarang.
if ($klm->destroyIfDue('partner1', 'key_v3')) {
    echo "kunci dihancurkan\n";
}

// Cek status saat ini:
echo $klm->statusOf('partner1', 'key_v1'); // active|retiring|revoked|destroyed
```

**Catatan crypto-shredding:** `scheduleDestroy()`/`destroyIfDue()` sengaja **tidak** menimpa/mengosongkan kolom secret — pencegahan dekripsi murni lewat gate status agar perilaku deterministik dan dapat diaudit. Pemusnahan fisik material adalah kebijakan DBA.

### Transisi Legal

| Operasi | Dari `active` | Dari `retiring` | Dari `revoked` | Dari `destroyed` |
|---------|---------------|-----------------|----------------|------------------|
| `retire()` | ✅ → retiring | ✅ (grace diperbarui) | ❌ **dilarang** | ❌ ditolak |
| `revoke()` | ✅ | ✅ | ✅ | ❌ ditolak |
| `scheduleDestroy()` | ✅ | ✅ | ✅ | ❌ ditolak |
| `destroyIfDue()` | ✅ bila due | ✅ bila due | ✅ bila due | — (`false`, tidak ada eksekusi baru) |

Dua prinsip yang menjelaskan tabel di atas:

1. **Anti-resurrect:** `retire()` menyetel `valid_until` masa depan, jadi `revoked → retiring` berarti menghidupkan kembali akses lewat grace window — karena itu dilarang (422).
2. **Operator selalu bisa mematikan kunci:** transisi yang *membatasi* akses (revoke, schedule destroy, eksekusi destroy) diizinkan dari status apa pun kecuali `destroyed`. Baris kunci tidak ada → `BAD_REQUEST`; pelanggaran transisi → `UNPROCESSABLE` (422).

## Dekripsi Arsip — `decryptArchivedLog()`

Use case: debug/dispute terhadap **arsip payload terenkripsi** lama meski kuncinya sudah dirotasi/di-revoke (selama belum destroyed). Parameter input `$log` merekonstruksi konteks verifikasi asli:

| Field arsip | Isi |
|-------------|-----|
| `client_id` / `key_id` | Identitas pemilik payload saat itu (menentukan baris kunci pembaca) |
| `ciphertext` | Raw body HTTP saat itu (JSON berisi field `__aead_b64`) |
| `headers` | Header request asli saat verifikasi (X-Nonce, X-Timestamp, X-Signature-Version, dst.) |
| `method` / `path` / `query` | Nilai yang dipakai **server** saat `verify()` asli (server-derived) |

Alur internal (fail-closed, replikasi persis parameter `RequestVerifier`): baca baris kunci arsip via SQL langsung → gate status → ambil material AEAD (`aead_key_b64`, atau unwrap `wrapped_b64` via KMS) → rekonstruksi nonce dari header + method/path/query **arsip** → HKDF subkey bila `deriveKeys` aktif → dekripsi dengan AAD versi + timestamp + bindHeaders.

```php
try {
    $plaintext = $klm->decryptArchivedLog([
        'client_id'  => $row->client_id,
        'key_id'     => $row->key_id,
        'ciphertext' => $row->raw_body,
        'headers'    => json_decode($row->request_headers, true),
        'method'     => $row->http_method,
        'path'       => $row->http_path,
        'query'      => $row->http_query,
    ]);
} catch (\SecurePayload\Exceptions\KeyDestroyedException $e) {
    // 410 — kunci arsip telah dihancurkan; plaintext mustahil dibuka lagi.
} catch (\SecurePayload\Exceptions\SecurePayloadException $e) {
    // 400/401/422/500 — lihat pemetaan di bawah.
}
```

### Pemetaan Exception

| Exception | HTTP | Kondisi |
|-----------|------|---------|
| `KeyDestroyedException` | **410** | Status kunci `destroyed` — dilempar standalone agar aplikasi menanganinya terpisah |
| `SecurePayloadException` UNAUTHORIZED | 401 | Kunci `revoked`; grace `retiring` habis (atau `valid_until` NULL); status tidak dikenal (fail-closed); dekripsi gagal (kunci/data salah) |
| `SecurePayloadException` BAD_REQUEST | 400 | Baris kunci tidak ditemukan; data arsip tidak lengkap; arsip mode `hmac` (tidak pernah punya ciphertext) |
| `SecurePayloadException` SERVER_ERROR | 500 | Material kunci rusak pada sisi server |
| `RuntimeException` | — | KMS belum di-inject padahal baris memakai wrapped key, atau unwrap KMS gagal |

### Asumsi Konfigurasi

Parameter dekripsi harus cocok dengan config saat payload asli diverifikasi:

- `deriveKeys`, `version`, dan `bindHeaders` pada konstruktor `KeyLifecycleManager` **wajib sama** dengan opsi instance `SecurePayload` yang memverifikasi request aslinya;
- mismatch tidak pernah menghasilkan plaintext salah — hasilnya **gagal-closed** (dekripsi gagal, 401);
- mode `hmac` murni tidak memiliki ciphertext sehingga arsipnya memang tak bisa didekripsi (400).

## Retensi Arsip vs Umur Kunci

Prinsip desain (#7): **masa simpan arsip tidak boleh melebihi masa hidup kunci yang melindunginya**, tetapi rotasi tidak berarti "hancurkan kunci lama seketika". Jika kunci dijadwalkan hancur sebelum masa retensi arsip berakhir, arsip otomatis jadi tak terbuka — sering bukan yang diinginkan.

Check doctor membandingkan keduanya dan memberi WARN untuk tiap kunci `active`/`retiring` yang `destroy_after`-nya jatuh **sebelum** retensi berakhir:

```bash
composer global require sk8dvlpr/securepayload-cli   # jika belum

securepayload doctor \
    --dsn="mysql:host=localhost;dbname=app" \
    --table=secure_keys \
    --retention-days=90
```

```
[OK] retention_vs_destroy — Semua kunci aktif/retiring bertahan melebihi ambang retensi 90 hari.
[WARN] retention_vs_destroy — Kunci partner1/key_v3 (status active) dijadwalkan hancur
       2026-09-01T00:00:00+07:00 — sebelum masa retensi 90 hari berakhir.
```

Exit code CLI = FAILURE bila ada entri FAIL (WARN hanya perlu perhatian). Programatik: `(new DoctorChecks())->run([], ['pdo' => $pdo, 'retention_days' => 90])` → daftar `['name','level','detail']`.

## Referensi API

| Class / Method | Peran |
|----------------|-------|
| `KeyLifecycleManager::__construct(PDO, opts, ?Kms)` | Wiring DB + opsi lifecycle + rekonstruksi config arsip |
| `::statusOf($clientId, $keyId)` | Baca status kunci saat ini |
| `::retire($clientId, $keyId, $graceSeconds)` | Set `retiring` + `valid_until`; dilarang dari revoked/destroyed |
| `::revoke($clientId, $keyId)` | Set `revoked` segera, hapus `valid_until`; dilarang dari destroyed saja |
| `::scheduleDestroy($clientId, $keyId, $ts)` | Tandai `destroy_after` (butuh `useDestroyAfter=true`) |
| `::destroyIfDue($clientId, $keyId, ?$now)` | Eksekusi destroy bila due; `true` = dieksekusi sekarang |
| `::decryptArchivedLog(array $log)` | Buka arsip payload dengan kunci pencatatnya (gate status ketat) |
| `KeyStatus::ACTIVE / RETIRING / REVOKED / DESTROYED` | Konstanta status |
| `DoctorChecks::run($env, $options)` | Audit konfigurasi, termasuk retensi vs destroy_after |
| `packages/cli`: `securepayload doctor` | Render check sebagai `[OK]/[WARN]/[FAIL]` + exit code |

## Invariant Keamanan

- **Retire dilarang dari `revoked`** — mencegah resurrect akses melalui grace window.
- **Operator selalu bisa revoke/schedule/destroy** dari status apa pun kecuali `destroyed`; kunci tidak bisa "terkunci" dari pemadamannya.
- `decryptArchivedLog()` membaca SQL langsung (bypass filter fail-closed `DbKeyProvider`) karena harus membedakan "hancur" vs "memang tidak ada" — keamanan tetap terjaga: identifier whitelist regex, semua nilai lewat prepared statement.
- Status **tidak dikenal** pada baris arsip ditolak fail-closed (401), bukan diloloskan.
- Header `X-Canonical-Request` arsip **tidak dipercaya** — nonce direkonstruksi dari method/path/query arsip (security invariant yang sama dengan protokol utama).
- Destroy tidak menimpa kolom secret; gate murni status — deterministik dan dapat diaudit.
- Detail error/check tidak pernah memuat isi secret (hanya panjang byte, status, timestamp).

---

## Rotasi Operasional — `KeyManager`

Prosedur rotasi kunci tanpa downtime client-server. Fitur ini **tidak mengubah wire protocol** — client tetap mengirim `X-Key-Id` eksplisit; server memuat kunci exact match selama masih dalam status `active` atau `retiring` (grace window).

### Prasyarat Rotasi

- `DbKeyProvider` dengan tabel `secure_keys` (composite PK: `client_id` + `key_id`)
- Backup database sebelum rotasi
- Kolom lifecycle (jalankan migrasi `docs/migrations/001_key_lifecycle.sql` — lihat "Persiapan Skema" di atas)
- Aktifkan filter lifecycle di server:

```php
$provider = new DbKeyProvider($pdo, [
    'useKeyLifecycle' => true,
]);
$keyLoader = fn (string $cid, string $kid): array => $provider->load($cid, $kid);
```

### Alur Rotasi Standar

1. Generate kunci baru + SQL migrasi:

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

echo $result->toSqlUpdateRetiring(); // UPDATE key_v1 -> retiring + valid_until
echo $result->toSqlInsertNew();      // INSERT key_v2 -> active

// Distribusi ke client (JANGAN simpan secret di server):
// - hmacSecret: $result->newKey->hmacSecret
// - aeadKeyB64: $result->newKey->aeadKeyB64
// - ed25519SecretKeyB64: $result->ed25519SecretKeyB64 (jika ada)
// - ed25519PublicKeyServerB64: $result->newKey->ed25519ServerPublicB64 (client verify response)
```

2. Jalankan SQL di database — urutan wajib: **UPDATE retiring dulu**, lalu **INSERT active**.
3. Rollout client bertahap: client lama tetap pakai `key_v1` (valid selama grace); client baru pindah ke `key_v2`; tidak perlu deploy simultan.
4. Monitor: pantau `EVENT_KEY_NOT_FOUND` / HTTP 401 setelah grace berakhir; spike 401 pada `key_v1` = client belum migrasi (perpanjang grace atau hubungi partner).
5. Cleanup setelah grace:

```php
// Revoke manual (segera):
echo $km->revokeKey('partner1', 'key_v1');

// Atau cron: tandai retiring expired sebagai revoked
echo $km->purgeExpiredRetiringKeys('secure_keys');
```

### Rotasi Env-only (Tanpa DB)

Untuk setup `EnvKeyProvider`: tambah env var baru (`SECUREPAYLOAD_{CID}_{KEY_V2}_HMAC_SECRET`, dll.) → deploy env + restart server → update client ke `KEY_V2` → hapus env `KEY_V1` setelah semua client migrasi. Tidak ada grace otomatis — overlap = periode di mana kedua env var masih ada.

### Rotasi dengan Ed25519 (`signAlg=ed25519`)

- **Client** menerima: `ed25519SecretKeyB64` (request signing) + `ed25519PublicKeyServerB64` (response verify)
- **Server DB** menyimpan: `ed25519_public_b64` (verify request) + `ed25519_server_secret_b64` / `ed25519_server_public_b64` (sign response)
- Aktifkan `useEd25519` + `useEd25519Server` di `DbKeyProvider`

### Invariant Keamanan Rotasi

- Server **tidak** mencoba multiple `keyId` otomatis saat verifikasi gagal
- Response signing memakai kunci server dari **kid yang sama** dengan request
- Replay nonce cache per `(clientId, keyId, nonce)` — rotasi tidak membagikan nonce antar keyId

### Referensi API Rotasi

| Class / Method | Peran |
|----------------|-------|
| `KeyManager::rotateKey()` | Generate kunci baru + SQL |
| `KeyManager::revokeKey()` | Revoke segera |
| `KeyManager::purgeExpiredRetiringKeys()` | Cron cleanup |
| `KeyRotationResult::toSqlUpdateRetiring()` | SQL UPDATE key lama |
| `KeyRotationResult::toSqlInsertNew()` | SQL INSERT key baru |
| `DbKeyProvider` + `useKeyLifecycle` | Filter active/retiring/revoked |
| `KeyStatus::ACTIVE / RETIRING / REVOKED` | Konstanta status |