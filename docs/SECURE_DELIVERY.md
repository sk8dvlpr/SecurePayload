# Secure Delivery — Tautan Unduhan Aman

Layer konsumsi file di atas `Storage/` (bisa juga dipakai standalone): penerbitan **URL ber-token** `sp1` untuk mengunduh file terenkripsi lewat endpoint broker Anda. Token diamankan HMAC-SHA256 dengan kedaluwarsa, opsi sekali-pakai, dan binding pemegang — tanpa menyentuh protokol request/response SecurePayload.

> ⚠️ **PERINGATAN TEGAS:** Modul `Storage/` **TIDAK BOLEH diekspos langsung dari luar** — jangan pernah membuka akses publik ke path blob, bucket, atau endpoint "ambil file by id" mentah. Satu-satunya jalur keluar adalah **endpoint broker**: verifikasi token dulu → baru streaming dari backend. Ini mitigasi risiko utama fitur delivery.

## Format Token

```
sp1.<base64url(payloadJSON)>.<base64url(signature)>
```

| Klaim | Tipe | Arti |
|-------|------|------|
| `file_id` | string | ID file yang boleh diakses |
| `exp` | int (unix) | Kedaluwarsa; pada detik `exp` token sudah kedaluwarsa |
| `iat` | int (unix) | Waktu terbit |
| `jti` | string (32 hex) | ID acak per token — dua `issue()` berparameter sama selalu menghasilkan token beda |
| `su` | bool | Sekali-pakai (`true` = butuh replayStore di Verifier) |
| `bound_to` | ?string | Identitas pemegang yang diikat (mis. client id); `null` = tidak terikat |

Signature = `hash_hmac('sha256', stringKanonik, $hmacSecret)` atas **string kanonik** (bukan byte JSON, sehingga urutan key tidak memengaruhi verifikasi):

```
implode("\n", ['sp1', file_id, exp, jti, su('1'|'0'), bound_to ?? ''])
```

Karena pemisahnya `\n`, `fileId` dan `boundTo` wajib non-kosong serta bebas whitespace/karakter kontrol (ditolak fail-closed oleh Issuer).

## Quick Start — Issuer

```php
use SecurePayload\Delivery\SecureLinkIssuer;

// Secret bersama Issuer & Verifier, minimal 32 karakter (rekomendasi 64 byte hex).
$issuer = new SecureLinkIssuer($hmacSecret, ['ttlMax' => 86400]); // batas TTL maksimum (default 24 jam)

$token = $issuer->issue(
    fileId:   $manifest->fileId(),
    ttl:      300,            // 5 menit
    singleUse: true,          // hanya bisa diverifikasi sekali
    boundTo:  'client_001',   // opsional: ikat ke pemegang
);

$url = "https://api.example.com/files/{$manifest->fileId()}?token={$token}";
// kirim $url ke pemegang yang berhak (email, response API, dsb.)
```

## Quick Start — Endpoint Broker

```php
use SecurePayload\Delivery\SecureLinkVerifier;

$fileId = $_GET['file'] ?? '';
$token  = $_GET['token'] ?? '';

// replayStore: fn(cacheKey, ttl): bool — true = pertama kali & sekaligus menandai.
// Pola sama dengan replay store protokol utama (Psr16ReplayStore / Redis SET NX).
$verifier = new SecureLinkVerifier($hmacSecret, new Psr16ReplayStore($cache));

$check = $verifier->verify($fileId, $token, boundTo: $currentUserId);
if (!$check['ok']) {
    http_response_code(403);                 // $check['error'] = alasan singkat
    exit('Akses ditolak.');
}
// $check['claims'] = {file_id, exp, iat, jti, su, bound_to}

$manifest = $manifestRepo->find($fileId);    // dari DB aplikasi Anda
if ($manifest === null || !$storage->exists($manifest)) {
    http_response_code(404);
    exit('File tidak ditemukan.');
}

// Header keamanan respons — WAJIB sebelum output:
header('Content-Type: application/pdf');
header('Content-Disposition: inline; filename="report.pdf"');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('X-Content-Type-Options: nosniff');

// Watermark forensik (plan §5.4): sisip identitas pemegang token ke dokumen
// SEBELUM satu byte pun dikirim. Hook gagal = respons dibatalkan (fail-closed),
// dokumen tidak pernah keluar tanpa watermark. Ukuran akhir body baru diketahui
// setelah hook jalan → JANGAN set Content-Length; pakai transfer chunked.
$claims = $check['claims'];
$requester = [
    'subject' => (string) ($claims['bound_to'] ?? 'anonim'),
    'jti'     => (string) $claims['jti'],
];

$storage->retrieveStream(
    $manifest,
    fn(string $chunk) => print $chunk,
    [
        'requester'    => $requester,
        // Kontrak: callable(string $plain, FileManifest $m, array $ctx): string
        // Contoh generik; untuk PDF nyata gunakan mpdf/mpdf di dalam hook ini.
        'beforeStream' => function (string $plain, FileManifest $m, array $ctx): string {
            $who = $ctx['requester']['subject'] ?? 'anonim';
            return "LISENSI: {$who} | file={$ctx['file_id']}\n" . $plain;
        },
    ]
);
```

Contoh endpoint runnable lengkap: [`examples/secure-delivery/download_endpoint.php`](../examples/secure-delivery/download_endpoint.php).

## Urutan Validasi (Fail-Closed)

`verify()` memeriksa tujuh langkah berurutan dan **berhenti pada kegagalan pertama**. Semua penolakan mengembalikan `['ok' => false, 'status' => 403, 'error' => <alasan>]` — **tidak melempar exception** — dan meng-emit event `file_access_denied`.

| # | Alasan penolakan | Kondisi |
|---|------------------|---------|
| 1 | `format_token` | Bukan 3 segmen, prefix bukan `sp1`, base64url rusak, atau payload bukan JSON dengan tipe klaim yang benar |
| 2 | `signature_invalid` | HMAC kanonik tidak cocok (`hash_equals`) ATAU secret berbeda |
| 3 | `file_mismatch` | `file_id` parameter ≠ `file_id` klaim di token |
| 4 | `token_expired` | `exp <= now` (pada detik `exp` sudah kedaluwarsa) |
| 5 | `replay_store_required` | `su=true` tetapi replayStore tidak dipasang — **fail-closed**, bukan dilewatkan |
| 6 | `token_reused` | `su=true` dan replayStore melaporkan `jti` sudah dipakai |
| 7 | `binding_mismatch` | Klaim `bound_to` ≠ parameter `boundTo`; ketat **dua arah** — token tak terikat + param non-null juga ditolak |

Sukses mengembalikan `['ok' => true, 'status' => 200, 'claims' => [...]]` dan meng-emit event `file_accessed`.

## Token Sekali-Pakai (Single-Use)

Token `su=true` membutuhkan **replayStore callable** pada Verifier dengan semantik identik replay store protokol utama:

- Kontrak: `fn(string $cacheKey, int $ttl): bool` — kembalikan `true` bila key belum pernah dipakai (dan sekaligus tandai), `false` jika sudah.
- Cache key: `'sp-link:' . hash('sha256', $jti)` — key **tidak** menyertakan timestamp: satu `jti` = satu pakai, titik. TTL store = sisa umur token (minimal 1 detik).
- **Tanpa store, semua token single-use DITOLAK** (`replay_store_required`). Lebih aman gagal-closed daripada memberikan ilusi sekali-pakai.
- Untuk bebas race-condition gunakan primitif atomik (Redis `SET NX`, Memcached `add()`) — pola lengkap ada di `examples/replay-store/` dan adapter `Psr16ReplayStore`.

## Binding Pemegang (`boundTo`)

Binding bersifat ketat dua arah: token terikat hanya sah untuk pemegang persis sama (`hash_equals`), dan token **tak terikat** tidak boleh diklaim terikat dengan mengisi param `boundTo`. Sertakan identitas sesi saat ini sebagai `boundTo` agar URL yang bocor tetap tidak berguna bagi pihak lain maupun pemiliknya sendiri setelah sesi berakhir.

## Event Audit

Diterima lewat opsi `onSecurityEvent` konstruktor Verifier (handler `(string $event, array $context)`, konteks non-secret):

| Event | Konteks | Kapan |
|-------|---------|-------|
| `EVENT_FILE_ACCESSED` (`file_accessed`) | `file_id` | Token lolos verifikasi |
| `EVENT_FILE_ACCESS_DENIED` (`file_access_denied`) | `reason`, `file_id` | Setiap penolakan (termasuk alasan singkatnya) |

```php
$verifier = new SecureLinkVerifier($hmacSecret, $store, [
    'onSecurityEvent' => function (string $event, array $ctx): void {
        error_log("[delivery] $event " . json_encode($ctx)); // arahkan ke SIEM/logger
    },
]);
```

## Referensi API

| Class / Method | Peran |
|----------------|-------|
| `SecureLinkIssuer::__construct($hmacSecret, opts)` | Wiring penerbit; `opts`: `ttlMax` (default 86400), `clock` |
| `SecureLinkIssuer::issue($fileId, $ttl, $singleUse, $boundTo)` | Terbitkan token `sp1.<payload>.<sig>` URL-safe |
| `SecureLinkIssuer::DEFAULT_TTL_MAX` | Batas TTL default (86400 detik / 24 jam) |
| `SecureLinkVerifier::__construct($hmacSecret, ?$replayStore, opts)` | Wiring verifier; `opts`: `clock`, `onSecurityEvent` |
| `SecureLinkVerifier::verify($fileId, $token, ?$boundTo)` | Validasi 7 langkah fail-closed; array result, tanpa exception |
| `Psr16ReplayStore` | Adapter cache PSR-16 → callable replayStore (pola reuse) |

## Invariant Keamanan

- Secret minimal **32 karakter** — konstruktor menolak lebih pendek; semua perbandingan rahasia memakai `hash_equals`.
- Signature dihitung atas **string kanonik**, bukan byte JSON — urutan key payload tidak bisa dimanfaatkan untuk bypass.
- Verifikasi berhenti pada kegagalan pertama; pesan error berupa kode singkat (`signature_invalid`, dll.) tanpa detail internal yang bisa membantu probing.
- `jti` acak per token: token identik-parameternya tetap unik, sehingga penggunaan ulang URL lama terdeteksi oleh replayStore.
- TTL dibatasi `ttlMax` (default 24 jam) — Issuer menolak `ttl` di luar `1..ttlMax`.
- Endpoint broker wajib memasang `Cache-Control: no-store` (respons unduhan tidak boleh dicache proxy/browser) dan `X-Content-Type-Options: nosniff` (mencegah MIME-sniffing).
- Modul Storage tidak pernah terekspos langsung; satu-satunya pintu adalah endpoint broker yang memverifikasi token lebih dahulu.
