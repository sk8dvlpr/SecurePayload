# Idempotency — Retry Aman untuk Operasi Bisnis

Store idempotensi untuk endpoint yang berisiko efek ganda (order, pembayaran, dedup event): retry yang **sah** dikembalikan hasil response aslinya tanpa mengeksekusi proses bisnis dua kali. Fitur ini sengaja **terpisah** dari `RequestVerifier` — aplikasi Anda yang memasangkannya.

## Idempotency vs Anti-Replay

Dua mekanisme dengan store mirip tapi tujuan bertolak belakang:

| Aspek | Anti-Replay (`replayStore`) | Idempotency (`IdempotencyStoreInterface`) |
|-------|-----------------------------|-------------------------------------------|
| Tujuan | **Keamanan** — cegah request ditangkap lalu dikirim ulang | **Keandalan bisnis** — selamatkan retry setelah timeout/network error |
| Nonce/kunci dipakai ulang | **DITOLAK** (401) | **DIIZINKAN** — dibalas hasil tersimpan |
| Kunci | Nonce protokol + timestamp window | Header `X-Idempotency-Key` dari client |
| Lokasi | Di dalam `RequestVerifier` | Di handler aplikasi (opsional) |

## Komponen

| Class | Peran |
|-------|-------|
| `IdempotencyStoreInterface` | Kontrak `get($key): ?array` dan `set($key, $result, $ttl)`; `ttl <= 0` = tanpa kedaluwarsa |
| `ArrayIdempotencyStore` | In-memory: dev/test/proses single-worker. Data hilang saat proses mati, tidak terbagi antar server. Expiry lazy (dibuang saat di-`get`) |
| `Psr16IdempotencyStore` | Membungkus cache PSR-16 apa pun (Redis/Memcached/APCu via adapter). Prefix default `'sp-idem-'`; nilai non-array dianggap tidak ada (fail-closed) |

```php
use SecurePayload\Idempotency\ArrayIdempotencyStore;
use SecurePayload\Idempotency\Psr16IdempotencyStore;

$store = new Psr16IdempotencyStore($psr16Cache);      // produksi multi-server
$store = new ArrayIdempotencyStore();                 // dev/test saja
```

## Pola Pemakaian

Aturan mainnya tiga: kunci datang dari header **`X-Idempotency-Key`**, hasil disimpan **sebelum efek samping dipublikasikan**, dan retry mengembalikan response tersimpan — bukan eksekusi ulang.

```php
use SecurePayload\Idempotency\Psr16IdempotencyStore;

$store = new Psr16IdempotencyStore($cache);

// 1. Wajibkan key pada operasi non-idempoten.
$idemKey = $_SERVER['HTTP_X_IDEMPOTENCY_KEY'] ?? '';
if ($idemKey === '' || strlen($idemKey) > 128) {
    http_response_code(400);
    exit(json_encode(['error' => 'Header X-Idempotency-Key wajib ada']));
}

// 2. Namespace per-endpoint agar key antar-route tidak bentrok.
$cacheKey = 'POST:/v1/payments:' . $idemKey;

// 3. Retry? Balas dari cache, jangan eksekusi ulang.
$saved = $store->get($cacheKey);
if ($saved !== null) {
    header('X-Idempotent-Replay: true');
    http_response_code((int) $saved['status']);
    header('Content-Type: application/json');
    echo $saved['body'];
    exit;
}

// 4. Eksekusi pertama — simpan hasil SEBELUM/meski efek samping gagal terpublikasi
//    parsial (pola "simpan dulu" mencegah dobel charge saat crash di tengah jalan).
$status   = 201;
$bodyJson = json_encode(processPayment(/* ... */));   // proses bisnis

$store->set($cacheKey, ['status' => $status, 'body' => $bodyJson], 86400);

http_response_code($status);
header('Content-Type: application/json');
echo $bodyJson;
```

### Posisi terhadap `RequestVerifier`

Library **tidak memaksa** integrasi ke verifikasi protokol — keputusan "eksekusi ulang vs balas dari cache" milik aplikasi. Penempatan alami: **setelah** `verify()` sukses, sebelum logika bisnis:

```php
$result = $server->verify(getallheaders(), file_get_contents('php://input'), $_SERVER['REQUEST_METHOD'], $path, $_GET);
if (!$result['ok']) { /* tolak */ }

$cacheKey = 'POST:' . $path . ':' . ($_SERVER['HTTP_X_IDEMPOTENCY_KEY'] ?? '');
if (($saved = $store->get($cacheKey)) !== null) {
    // payload sudah pernah diproses — balas hasil lama, JANGAN eksekusi lagi.
}
```

## Batasan Atomicity

Operasi get-then-set **bukan atomik**: dua retry berkunci sama yang tiba nyaris bersamaan bisa sama-sama melihat `get() === null` lalu mengeksekusi dua kali. Untuk mayoritas aliran idempotency (retry setelah timeout) ini dapat diterima; bila butuh jaminan ketat *exactly-once*, gunakan primitif atomik backend (mis. Redis `SET NX`) sebagai gerbang eksekusi di layer aplikasi, dan pakai store hanya sebagai penyimpan hasil.

## Catatan Keamanan

- `set()` menyimpan hasil ke shared cache — **jangan memuat data rahasia** (token, secret, PII sensitif) dalam `$result`; simpan body response yang memang ditujukan ke client.
- Namespace kunci per-endpoint (route/method) agar idempotency key client tidak melompat antar fitur.
- Validasi panjang/format key sebelum dipakai sebagai bagian cache key (mencegah key abuse/panjang tak wajar).
- TTL pilih secukupnya (umum 1–24 jam): terlalu pendek membuka jendela retry ganda, terlalu panjang menumpuk entri.

## Referensi API

| Class / Method | Peran |
|----------------|-------|
| `IdempotencyStoreInterface::get($key)` | Ambil hasil tersimpan; `null` = belum ada / kedaluwarsa |
| `IdempotencyStoreInterface::set($key, $result, $ttl)` | Simpan hasil; `ttl <= 0` = tanpa kedaluwarsa |
| `ArrayIdempotencyStore` | Implementasi in-memory (dev/test/single-worker) |
| `Psr16IdempotencyStore::__construct(CacheInterface, $prefix)` | Adapter PSR-16; prefix default `'sp-idem-'` |
