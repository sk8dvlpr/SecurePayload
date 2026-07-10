# SecurePayload

> **Library PHP untuk mengamankan komunikasi HTTP antar-server (S2S) maupun Client–Server.**
>
> Tandatangani (HMAC-SHA256), enkripsi (AEAD XChaCha20-Poly1305), dan lindungi request dari serangan replay — semuanya lewat satu class inti.

[![CI](https://img.shields.io/github/actions/workflow/status/sk8dvlpr/securepayload/ci.yml?branch=main&label=CI&style=flat-square)]()
[![PHP Version](https://img.shields.io/badge/php-%E2%89%A5%208.0-blue?style=flat-square)]()
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)]()
[![Packagist Version](https://img.shields.io/packagist/v/sk8dvlpr/securepayload.svg?style=flat-square)](https://packagist.org/packages/sk8dvlpr/securepayload)

**SecurePayload** adalah library PHP 8.0+ yang *framework-agnostic* untuk mengamankan pertukaran data lewat HTTP. Satu class `SecurePayload` berperan sebagai **kedua sisi** sekaligus — sisi *client* (membangun, menandatangani, mengenkripsi request) dan sisi *server* (memverifikasi, mendekripsi request) — tergantung method mana yang Anda panggil. Dilengkapi subsistem **KMS** untuk manajemen kunci per-client dan *key-wrapping*.

---

## 📖 Apa yang Dilakukan Library Ini?

Saat dua sistem saling bertukar data lewat HTTP, ada tiga risiko utama:

1. **Pemalsuan / perubahan data** — penyerang mengubah isi request di tengah jalan.
2. **Penyadapan** — isi request terbaca pihak ketiga.
3. **Replay attack** — penyerang menangkap request sah lalu mengirim ulang.

SecurePayload mengatasi ketiganya dengan menyisipkan sekumpulan header keamanan standar (`X-Signature`, `X-Timestamp`, `X-Nonce`, `X-AEAD-*`, dll.) ke dalam request, lalu memverifikasinya di sisi penerima:

- **Integritas & otentikasi** melalui HMAC-SHA256 atas representasi *canonical* dari method, path, query, dan digest body.
- **Kerahasiaan** melalui enkripsi AEAD XChaCha20-Poly1305 pada body.
- **Anti-replay** melalui kombinasi validasi timestamp (toleransi *clock skew*) dan cache *nonce* sekali-pakai.

---

## 🌟 Fitur Utama

- **Tiga mode keamanan** yang dipilih saat konstruksi:
  - `hmac` — hanya tanda tangan (integritas + otentikasi, tanpa enkripsi).
  - `aead` — hanya enkripsi (kerahasiaan + integritas via AEAD tag).
  - `both` — enkripsi **dan** tanda tangan (keamanan maksimal; tanda tangan dibuat atas *plaintext*, bukan ciphertext).
- **Algoritma tanda tangan** (`signAlg`):
  - `hmac` — HMAC-SHA256 (default, secret simetris).
  - `ed25519` — tanda tangan asimetris (client pegang private key, server pegang public key) untuk *non-repudiation*.
  - `hybrid-mldsa44-ed25519` — hybrid Ed25519 + ML-DSA-44 (butuh `pqSigner` yang di-inject; lihat [docs/POST_QUANTUM.md](docs/POST_QUANTUM.md)).
- **Protokol wire** — default `version` = `'4'` (`SecurePayload::DEFAULT_VERSION`). Client & server harus memakai nilai yang sama; set `version => '3'` bila perlu tetap di protokol v3.
- **Proteksi anti-replay** dengan timestamp + nonce. Nonce diingat selama `replayTtl + clockSkew` agar tidak ada celah waktu yang bisa dieksploitasi.
- **Canonicalization simetris** — client & server menghasilkan representasi request yang identik, sehingga verifikasi tahan terhadap manipulasi urutan query atau format path.
- **Anti signature-spoofing** — server **menurunkan** method/path/query dari input request-nya sendiri, bukan dari header `X-Canonical-Request` (header itu hanya petunjuk debug).
- **Transfer file aman** — in-memory (`buildFilePayload`), streaming dua langkah (`buildFileStream` + unggah ciphertext), atau **satu request multipart** (`buildFileStreamMultipartRequest` / `verifyFileStreamMultipart`).
- **Webhook helper** — `WebhookVerifier` membaca method/path/query dari `$_SERVER` (termasuk fallback header nginx/FPM).
- **Observability** — hook `onSecurityEvent`, `PrometheusSecurityExporter`, dan `OpenTelemetrySecurityExporter` (tracer opsional).
- **Interop RFC 9421** — `Rfc9421Bridge` memetakan header SecurePayload ↔ `Signature-Input` / `Signature` / `Content-Digest` (HMAC-SHA256).
- **Key Management System (KMS)** — provider kunci dari ENV atau Database (PDO), plus *key-wrapping* (Local / Vault / AWS / GCP / Azure).
- **Soft dependency `ext-sodium`** — jalur HMAC-only tetap berfungsi tanpa ekstensi sodium.
- **SDK & middleware** — PHP core; Node (`packages/node-sdk`, Express/Fastify); Go (`packages/go-sdk`, Gin/Echo/Fiber). Package framework resmi di `packages/`.

---

## ✅ Keunggulan

- **Satu class untuk dua sisi** — tidak perlu library terpisah untuk client dan server; logika signing & verifying dijamin konsisten.
- **Aman secara default** — semua perbandingan rahasia memakai `hash_equals` (konstan-waktu), mode `both` tidak bisa di-*downgrade* diam-diam menjadi HMAC-only, dan nonce AEAD diturunkan terikat pada konteks request (mencegah *nonce relocation*).
- **Validasi kunci ketat** — HMAC secret minimal 32 karakter, kunci AEAD wajib tepat 32 byte.
- **Siap produksi multi-server** — titik ekstensi `replayStore` memungkinkan cache nonce terpusat (Redis/Memcached).
- **Kompatibel PHP 8.0–8.3**, `declare(strict_types=1)`, dan lolos PHPStan level 5.
- **Pesan error terstruktur** — `SecurePayloadException` membawa kode HTTP (400/401/422/500) dan `context` untuk debugging.

---

## 📦 Instalasi

```bash
composer require sk8dvlpr/securepayload
```

**Requirements:**

- PHP **8.0** atau lebih baru.
- Ekstensi `ext-json`, `ext-hash` (wajib).
- Ekstensi `ext-sodium` (wajib **hanya** untuk mode `aead`/`both`).
- Ekstensi `ext-curl` (opsional, fallback default untuk `send()`/`sendFile()` jika `httpTransport` tidak diset).
- `psr/http-client` + `psr/http-factory` (opsional, untuk `SecurePayload\Http\Psr18Transport`).

---

## 🔑 Menyiapkan Kunci

| Mode   | signAlg   | Kunci client                          | Kunci server (via keyLoader)          |
| :----- | :-------- | :------------------------------------ | :------------------------------------ |
| `hmac` | `hmac`    | `hmacSecretRaw` (**≥ 32 karakter**)   | `hmacSecret` (sama)                    |
| `hmac` | `ed25519` | `ed25519SecretKeyB64` (64 byte)       | `ed25519PublicKeyB64` (32 byte)       |
| `hmac` | `hybrid-mldsa44-ed25519` | Ed25519 secret + ML-DSA secret + `pqSigner` | Ed25519 public + ML-DSA public + `pqSigner` |
| `aead` | —         | `aeadKeyB64` (**tepat 32 byte**)      | `aeadKeyB64` (sama)                    |
| `both` | `hmac`    | `hmacSecretRaw` + `aeadKeyB64`        | `hmacSecret` + `aeadKeyB64`           |
| `both` | `ed25519` | `ed25519SecretKeyB64` + `aeadKeyB64`  | `ed25519PublicKeyB64` + `aeadKeyB64`  |
| `both` | `hybrid-mldsa44-ed25519` | Ed25519 + ML-DSA + AEAD + `pqSigner` | public Ed25519/ML-DSA + AEAD + `pqSigner` |

Cara cepat membangkitkan kunci yang valid:

```php
$hmacSecret = bin2hex(random_bytes(32));            // 64 karakter hex
$aeadKeyB64 = base64_encode(random_bytes(32));      // 32 byte → base64

// Pasangan Ed25519 (butuh ext-sodium):
$pair       = sodium_crypto_sign_keypair();
$ed25519SecretKeyB64 = base64_encode(sodium_crypto_sign_secretkey($pair)); // client
$ed25519PublicKeyB64 = base64_encode(sodium_crypto_sign_publickey($pair)); // server
```

> ℹ️ Default protokol adalah **`'4'`**. Client & server harus memakai `version` yang sama. Untuk tetap di v3: `'version' => '3'`. Spesifikasi: [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

---

## 🚀 Penggunaan — Sisi Client (Pengirim)

Sisi client membangun header keamanan dan body yang sudah diproses.

```php
use SecurePayload\SecurePayload;

$client = new SecurePayload([
    'mode'          => 'both',                 // 'hmac' | 'aead' | 'both'
    'clientId'      => 'client_001',           // wajib di sisi client
    'keyId'         => 'key_v1',               // wajib di sisi client
    'hmacSecretRaw' => $hmacSecret,            // ≥ 32 karakter
    'aeadKeyB64'    => $aeadKeyB64,            // base64 dari 32 byte
]);

$url     = 'https://api.tujuan.com/v1/resource?limit=10';
$payload = ['user_id' => 123, 'action' => 'debit', 'amount' => 50000];

// Bangun header + body. Body sudah dienkripsi (mode aead/both).
[$headers, $body] = $client->buildHeadersAndBody($url, 'POST', $payload);

// Kirim memakai HTTP client apa pun (Guzzle, Symfony HttpClient, dll.):
// $response = $guzzle->post($url, ['headers' => $headers, 'body' => $body]);
```

### Helper `send()` (cURL atau PSR-18)

`send()` / `sendFile()` memakai `HttpTransportInterface`. Default: `CurlTransport` jika `ext-curl` tersedia. Atau injek transport PSR-18:

```php
use SecurePayload\Http\Psr18Transport;

$transport = new Psr18Transport($psr18Client, $requestFactory, $streamFactory);
$client = new SecurePayload([
    // ... kunci client ...
    'httpTransport' => $transport,
]);

$res = $client->send($url, 'POST', $payload);
// $res = ['status' => int, 'headers' => array, 'body' => mixed, 'error' => ?string]
```

Tanpa cURL maupun `httpTransport`, `send()` melempar exception yang jelas.

### SDK lintas bahasa (Node.js & Go)

Partner non-PHP dapat memakai implementasi protokol v3 yang **byte-exact** dengan PHP core:

| SDK | Path | Uji |
|-----|------|-----|
| Node.js/TypeScript | [`packages/node-sdk`](packages/node-sdk) | `npm test` |
| Go | [`packages/go-sdk`](packages/go-sdk) | `go test ./...` |

Spesifikasi normatif: [`docs/PROTOCOL.md`](docs/PROTOCOL.md). Test vectors: [`docs/fixtures/v3/`](docs/fixtures/v3/).

### CLI operasional (`securepayload-cli`)

```bash
composer global require sk8dvlpr/securepayload-cli

securepayload keys:generate client-a key-v1
securepayload keys:rotate client-a key-v1 --grace=86400
securepayload debug:verify -H headers.json -b @body.json --method=POST --path=/v1/pay
securepayload test:roundtrip --mode=both
```

Package: [`packages/cli`](packages/cli/). Framework packages: [`packages/`](packages/).

### Mengirim file

```php
// Membangun payload file (tanpa mengirim):
[$headers, $body] = $client->buildFilePayload(
    $url,
    'POST',
    '/path/ke/dokumen.pdf',
    ['keterangan' => 'Invoice Juni'],   // data tambahan (opsional)
    'invoice.pdf'                        // nama kustom (opsional)
);

// Atau langsung kirim via cURL:
$res = $client->sendFile($url, 'POST', '/path/ke/dokumen.pdf', ['user_id' => 123]);
```

> ⚠️ **Peringatan memori:** `buildFilePayload()`/`sendFile()` memuat seluruh file ke RAM lalu meng-encode base64 (+33% overhead). Aman untuk file **≤ 10MB** pada `memory_limit` default. Untuk file besar, gunakan **streaming** (di bawah) atau `multipart/form-data` biasa dan cukup tandatangani hash file-nya.

### Mengirim file besar (Streaming AEAD)

Untuk file besar, `buildFileStream()` mengenkripsi **per-chunk** memakai XChaCha20-Poly1305 *secretstream* — tanpa memuat seluruh file ke memori. Hasilnya: file ciphertext + **manifest** kecil yang dikirim & ditandatangani lewat jalur request biasa.

```php
// Client: enkripsi streaming → manifest (chunk 64KiB–1MiB direkomendasikan).
$manifest = $client->buildFileStream('/path/besar.zip', '/tmp/out.sps', ['name' => 'besar.zip'], 256 * 1024);
[$headers, $body] = $client->buildHeadersAndBody('https://api/upload/manifest', 'POST', $manifest);
// kirim $headers+$body (manifest), lalu unggah file ciphertext /tmp/out.sps terpisah.

// Server: verifikasi manifest (request aman) lalu dekripsi + validasi file.
$manifest = $server->verify($headers, $body, 'POST', '/upload/manifest', [])['json'];
$res = $server->verifyFileStream('/tmp/uploaded.sps', $manifest, '/tmp/plain.zip', [
    'max_size' => 100 * 1024 * 1024, 'allowed_exts' => ['zip'], 'strict_mime' => true,
]);
// $res['file']['path'] berisi plaintext aman. Gagal-tertutup: file parsial dihapus bila verifikasi gagal.
```

> 💾 **Memori & chunk:** pemakaian RAM ≈ satu chunk (default 64 KiB; rentang 1 KiB–8 MiB). Chunk **256 KiB–1 MiB** efisien untuk file besar. Kunci stream memakai `aeadKeyB64` instance (mendukung `deriveKeys`). Proteksi truncation/append (TAG_FINAL) + digest ciphertext aktif. Lihat `examples/file-stream/`.

### File stream dalam satu request (multipart)

`buildFileStreamMultipartRequest()` mengenkripsi file per-chunk, menandatangani/mengamankan **manifest** lewat jalur `buildHeadersAndBody`, lalu membungkus hasilnya sebagai `multipart/form-data` (part `payload` = body SecurePayload untuk manifest; part `ciphertext` = bytes secretstream). Header `X-SP-Multipart: 1` menandai request ini.

```php
[$headers, $multipartBody, $contentType] = $client->buildFileStreamMultipartRequest(
    'https://api.tujuan.com/v1/upload',
    'POST',
    '/path/besar.zip',
    ['name' => 'besar.zip'],
    256 * 1024
);
// Kirim $headers + $multipartBody dengan Content-Type dari $contentType (atau $headers['Content-Type']).

$res = $server->verifyFileStreamMultipart(
    $headers,
    $multipartBody,
    'POST',
    '/v1/upload',
    [],
    '/tmp/plain.zip',
    ['max_size' => 100 * 1024 * 1024, 'allowed_exts' => ['zip'], 'strict_mime' => true]
);
if ($res['ok']) {
    // $res['file']['path'] → plaintext; $res['verify'] → hasil verify() pada part payload
}
```

Alur dua langkah (`buildFileStream` + unggah `.sps` terpisah) tetap tersedia untuk protokol v3 maupun sebagai low-level di v4.

---

## 🛡️ Penggunaan — Sisi Server (Penerima)

Sisi server memverifikasi request masuk. Server **memuat kunci** lewat callable `keyLoader` berdasarkan `clientId` + `keyId`.

> 🔒 **Penting:** Server **wajib** memberikan `method`, `path`, dan `query` secara eksplisit dari input request-nya sendiri. Jangan pernah membacanya dari header `X-Canonical-Request` — itu akan membuka celah pemalsuan tanda tangan.

```php
use SecurePayload\SecurePayload;
use SecurePayload\KMS\EnvKeyProvider;

$provider = new EnvKeyProvider();

$server = new SecurePayload([
    'mode'      => 'both',
    'keyLoader' => fn(string $cid, string $kid): array => $provider->load($cid, $kid),
]);

$result = $server->verify(
    getallheaders(),                                   // header request
    file_get_contents('php://input'),                  // raw body
    $_SERVER['REQUEST_METHOD'],                         // method (dari server)
    parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH),  // path   (dari server)
    $_GET                                              // query  (dari server)
);

if (!$result['ok']) {
    http_response_code($result['status'] ?? 401);
    echo json_encode(['error' => $result['error']]);
    exit;
}

// Berhasil. Data terverifikasi (dan terdekripsi) tersedia di sini:
$data = $result['json'];          // array hasil decode JSON
$raw  = $result['bodyPlain'];     // string plaintext mentah
$mode = $result['mode'];          // 'HMAC' | 'AEAD' | 'BOTH' | 'BOTH-AEAD'
```

### Webhook / native PHP (`WebhookVerifier`)

Untuk endpoint webhook, `WebhookVerifier` mengekstrak method, path, dan query dari `$_SERVER` (plus fallback header bila `getallheaders()` tidak tersedia di nginx/FPM), lalu mendelegasikan ke `verify()`:

```php
use SecurePayload\Webhook\WebhookVerifier;

$verifier = new WebhookVerifier($server);
$result = $verifier->verifyFromGlobals($_SERVER, (string) file_get_contents('php://input'));
// atau: $verifier->verifyFromRequest($headers, $rawBody, $method, $path, $query);
```

Contoh: [`examples/webhook/verify.php`](examples/webhook/verify.php).

### Pilihan API verifikasi

| Method                | Perilaku                                                                                  |
| :-------------------- | :---------------------------------------------------------------------------------------- |
| `verify(...)`         | Aman, mengembalikan `['ok' => bool, 'status', 'error', 'debug', 'mode', 'bodyPlain', 'json']`. |
| `verifyOrThrow(...)`  | Melempar `SecurePayloadException` bila gagal; mengembalikan `['mode','bodyPlain','json']`. |
| `verifySimple(...)`   | Seperti `verify()` tanpa argumen query (untuk endpoint tanpa query string).               |
| `verifyFilePayload()` | Verifikasi + ekstraksi & validasi lampiran file (lihat di bawah).                          |

### Verifikasi file di server

```php
$res = $server->verifyFilePayload(
    getallheaders(),
    file_get_contents('php://input'),
    $_SERVER['REQUEST_METHOD'],
    parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH),
    [
        'max_size'        => 2 * 1024 * 1024,    // batas 2MB
        'allowed_exts'    => ['jpg', 'png', 'pdf'], // whitelist (opsional)
        'block_dangerous' => true,               // blokir .php/.exe/.sh/dll
        'strict_mime'     => true,               // deep-scan magic bytes (anti-spoof)
    ]
);

if ($res['ok']) {
    file_put_contents('/storage/' . $res['file']['name'], $res['file']['content_decoded']);
    $extraData = $res['data']; // data non-file dalam payload
}
```

---

## 🔏 Tanda Tangan Asimetris (Ed25519)

Secara default tanda tangan memakai HMAC-SHA256 (`signAlg => 'hmac'`), yang bersifat **simetris** — server menyimpan secret yang sama dengan yang dipakai client untuk menandatangani. Untuk skenario yang membutuhkan *non-repudiation* dan blast-radius lebih kecil (server hanya menyimpan **public key**, sehingga tidak bisa memalsukan request client), gunakan `signAlg => 'ed25519'`.

**Client** menandatangani dengan private key:

```php
$client = new SecurePayload([
    'mode'                => 'both',          // atau 'hmac'
    'signAlg'             => 'ed25519',
    'clientId'            => 'client_001',
    'keyId'               => 'key_v1',
    'ed25519SecretKeyB64' => $ed25519SecretKeyB64, // 64 byte, base64
    'aeadKeyB64'          => $aeadKeyB64,           // hanya untuk mode aead/both
]);

[$headers, $body] = $client->buildHeadersAndBody($url, 'POST', $payload);
// Header X-Signature-Algorithm akan berisi "ED25519".
```

**Server** memverifikasi dengan public key (lewat `keyLoader`):

```php
$server = new SecurePayload([
    'mode'      => 'both',
    'signAlg'   => 'ed25519',
    'keyLoader' => fn($cid, $kid) => [
        'hmacSecret'          => null,
        'aeadKeyB64'          => $aeadKeyB64,
        'ed25519PublicKeyB64' => $ed25519PublicKeyB64, // 32 byte, base64
    ],
]);

$result = $server->verify(getallheaders(), $rawBody, $method, $path, $query);
```

> 🔒 **Anti-downgrade:** server menentukan algoritma dari `signAlg` miliknya, bukan dari header `X-Signature-Algorithm`. Request bertanda tangan HMAC akan ditolak oleh server `ed25519`, dan sebaliknya.

Bangkitkan pasangan kunci lewat `KeyManager`:

```php
use SecurePayload\KMS\KeyManager;

$pair = (new KeyManager())->generateEd25519KeyPair();
// $pair['publicB64']  -> simpan di server / DB (kolom ed25519_public_b64)
// $pair['secretB64']  -> berikan ke client, JANGAN simpan di server
```

### Hybrid Ed25519 + ML-DSA-44

Untuk tanda tangan hybrid (Ed25519 ‖ ML-DSA-44), set `signAlg => 'hybrid-mldsa44-ed25519'` dan inject implementasi `SecurePayload\Crypto\PqSignerInterface` lewat opsi `pqSigner`. Wire header memakai `HYBRID-MLDSA44-ED25519`; nilai signature adalah `base64(ed25519_sig ‖ mldsa_sig)`.

```php
$client = new SecurePayload([
    'mode'                => 'hmac',
    'signAlg'             => 'hybrid-mldsa44-ed25519',
    'pqSigner'            => $pqSigner,              // wajib
    'clientId'            => 'client_001',
    'keyId'               => 'key_v1',
    'ed25519SecretKeyB64' => $ed25519SecretKeyB64,
    'mldsaSecretKeyB64'   => $mldsaSecretKeyB64,
]);
```

Library **tidak** membundle implementasi ML-DSA produksi; adapter liboqs/FIPS 204 disuplai aplikasi. Detail wire & field kunci: [`docs/POST_QUANTUM.md`](docs/POST_QUANTUM.md).

---

## 🔄 Pengamanan Response (Two-Way Integrity)

Secara default library hanya mengamankan **request**. Agar client juga bisa memastikan response benar-benar dari server dan tidak diubah, gunakan `buildResponse()` (server) dan `verifyResponse()` (client). Response **diikat ke nonce request asal** sehingga tidak bisa dipindah ke request lain.

**Server** membangun response setelah memverifikasi request:

```php
// $reqHeaders = header request masuk (getallheaders()); $server = instance bermode hmac/aead/both
[$respHeaders, $respBody] = $server->buildResponse($reqHeaders, ['status' => 'ok', 'data' => $hasil]);

// Kirim $respHeaders + $respBody sebagai response HTTP.
foreach ($respHeaders as $k => $v) { header("$k: $v"); }
echo $respBody;
```

**Client** memverifikasi response memakai nonce request yang ia kirim:

```php
[$reqHeaders, $reqBody] = $client->buildHeadersAndBody($url, 'POST', $payload);
$reqNonce = $reqHeaders[SecurePayload::HX_NONCE];

// ... kirim request, terima $responseHeaders + $responseBody ...

$res = $client->verifyResponse($responseHeaders, $responseBody, $reqNonce);
if ($res['ok']) {
    $data = $res['json'];   // response terverifikasi (dan terdekripsi pada mode aead/both)
}
```

Perilaku per mode (mengikuti mode instance):

| Mode   | Proteksi response                                              |
| :----- | :------------------------------------------------------------- |
| `hmac` | Tanda tangan HMAC-SHA256 atas plaintext.                       |
| `aead` | Enkripsi XChaCha20-Poly1305 (autentisitas via AEAD tag).      |
| `both` | Enkripsi **dan** tanda tangan HMAC.                            |

> ℹ️ **Tentang Ed25519 pada response:** tanda tangan response selalu memakai **HMAC-SHA256** dengan secret bersama, bukan Ed25519 — server tidak memegang private key client. Maka untuk response bertanda tangan (mode `hmac`/`both`), sediakan juga `hmacSecretRaw` (client) dan `hmacSecret` (server), termasuk saat request memakai `signAlg => 'ed25519'`. Pada mode `aead`/`both`, kerahasiaan + integritas response dijamin oleh AEAD.

---

## 🔗 Binding Timestamp & Header Kritikal ke AAD

Pada mode `aead`/`both`, `X-Timestamp` request **selalu** diikat ke AAD AEAD — manipulasi timestamp otomatis menggagalkan dekripsi (bukan sekadar ditolak validasi kesegaran). Timestamp response (`X-Resp-Timestamp`) diikat dengan cara yang sama.

Selain itu, header aplikasi yang kritikal dapat diikat lewat opsi `bindHeaders`. Nilainya disuplai di sisi client melalui `$extraHeaders`, dan dibaca server dari request masuk. Konfigurasi **wajib identik** di kedua sisi (nama header case-insensitive).

```php
$opts = [ /* ...mode, kunci... */ 'bindHeaders' => ['X-Request-Id'] ];
$client = new SecurePayload($opts + ['clientId' => 'c1', 'keyId' => 'k1', /* kunci client */]);
$server = new SecurePayload($opts + ['keyLoader' => $loader]);

// Client: nilai header diikat ke AAD DAN ikut terkirim.
[$headers, $body] = $client->buildHeadersAndBody(
    'https://api.com/v1/data', 'POST', ['x' => 1],
    ['X-Request-Id' => 'req-abc-123']
);

// Server: membaca X-Request-Id dari request; jika diubah/dihapus, dekripsi gagal.
$res = $server->verify($headers, $body, 'POST', '/v1/data', []);
```

> ⚠️ Nilai header yang diikat **harus sama** dengan yang benar-benar terkirim ke server. Bila memakai `send()`/`sendFile()`, teruskan header tersebut lewat argumen `$extraHeaders` agar konsisten.

---

## 🔑 Derivasi Subkey via HKDF (`deriveKeys`)

Secara default satu kunci dipakai langsung untuk satu fungsi. Dengan `deriveKeys => true`, kunci HMAC & AEAD yang Anda suplai diperlakukan sebagai **master key**, dan SecurePayload menurunkan **subkey berbeda per-fungsi** memakai HKDF-SHA256. Hasilnya: kebocoran satu subkey (mis. subkey enkripsi response) tidak otomatis membahayakan fungsi lain (signing request, dll).

```php
$opts = [ /* ...mode, kunci... */ 'deriveKeys' => true ];
$client = new SecurePayload($opts + ['clientId' => 'c1', 'keyId' => 'k1', /* kunci client */]);
$server = new SecurePayload($opts + ['keyLoader' => $loader]);
```

Subkey diturunkan untuk empat fungsi terpisah: enkripsi request (`sp-aead-req`), enkripsi response (`sp-aead-resp`), signing request (`sp-sign-req`), dan signing response (`sp-sign-resp`) — label `info` HKDF juga diikat ke versi protokol.

Helper publik tersedia bila Anda butuh derivasi sendiri:

```php
$subkey = SecurePayload::deriveKey($masterKey, 'sp-aead-req'); // 32 byte biner
```

> ⚠️ **Wajib sinkron:** `deriveKeys` harus sama di client & server. Bila tidak cocok, verifikasi **gagal-tertutup** (signature/dekripsi invalid) — tidak ada downgrade diam-diam. Opsi ini *opt-in* dan tidak mengubah perilaku default. Tidak berlaku untuk signing **Ed25519** / **hybrid** (material asimetris / PQ).

---

## 📊 Observability & Audit Hooks (`onSecurityEvent`)

Pasang callback observasional untuk meneruskan event keamanan ke SIEM, logger, atau rate-limiter. Murni aditif — **tidak mengubah alur verifikasi**, dan exception dari callback ditelan agar tidak pernah memengaruhi keamanan.

```php
$server = new SecurePayload([
    'mode' => 'both',
    'keyLoader' => $loader,
    'onSecurityEvent' => function (string $event, array $context): void {
        // $context hanya berisi data non-rahasia (clientId, keyId, alasan) — tanpa secret/plaintext.
        error_log("[security] $event " . json_encode($context));
        // mis. tambah counter rate-limit per $context['clientId'] di sini.
    },
]);
```

Event yang diemit (lihat konstanta `SecurePayload::EVENT_*`):

| Konstanta                   | Nilai                | Kapan                                            |
| :-------------------------- | :------------------- | :----------------------------------------------- |
| `EVENT_TIMESTAMP_INVALID`   | `timestamp_invalid`  | Timestamp di luar jendela kesegaran.             |
| `EVENT_REPLAY_DETECTED`     | `replay_detected`    | Nonce sudah pernah dipakai (replay).             |
| `EVENT_DECRYPT_FAILED`      | `decrypt_failed`     | Dekripsi AEAD gagal (kunci salah / data rusak).  |
| `EVENT_SIGNATURE_INVALID`   | `signature_invalid`  | HMAC/Ed25519 tidak valid.                        |
| `EVENT_KEY_NOT_FOUND`       | `key_not_found`      | Kunci server (HMAC/AEAD/public) tidak tersedia.  |
| `EVENT_NONCE_MISMATCH`      | `nonce_mismatch`     | Nonce AEAD tidak sesuai konteks request.         |

> Context tiap event memuat `clientId`/`keyId` plus penanda ringan (`source`/`alg`/`kind`/`scope`). **Tidak pernah** memuat secret, plaintext, atau ciphertext.

### Exporter Prometheus (Phase 15)

`PrometheusSecurityExporter` menghitung counter `securepayload_security_events_total` dari hook yang sama — tanpa boilerplate custom:

```php
use SecurePayload\Observability\PrometheusSecurityExporter;

$exporter = new PrometheusSecurityExporter();
$server = new SecurePayload([
    'mode' => 'both',
    'keyLoader' => $loader,
    'onSecurityEvent' => $exporter->onSecurityEvent(),
]);

// Endpoint /metrics (native PHP):
header('Content-Type: text/plain; version=0.0.4; charset=utf-8');
echo $exporter->render();
```

Label `client_id` / `key_id` **opt-in** (`includeClientId`, `includeKeyId`) — default hanya `event` untuk menghindari cardinality tinggi. Contoh server: [`examples/observability/prometheus.php`](examples/observability/prometheus.php).

### OpenTelemetry

`OpenTelemetrySecurityExporter` menulis span dari event yang sama. Tanpa tracer, callback menjadi no-op. Pasang tracer dari `open-telemetry/sdk` (opsional) bila tersedia:

```php
use SecurePayload\Observability\OpenTelemetrySecurityExporter;

$otel = new OpenTelemetrySecurityExporter([
    'tracer' => $tracer, // objek dengan spanBuilder()/startSpan(); boleh null
]);
$server = new SecurePayload([
    'mode' => 'both',
    'keyLoader' => $loader,
    'onSecurityEvent' => $otel->onSecurityEvent(),
]);
```

Contoh gabungan Prometheus + OTel: [`examples/observability/opentelemetry.php`](examples/observability/opentelemetry.php).

---

## 🔗 Interop RFC 9421 (`Rfc9421Bridge`)

`SecurePayload\Interop\Rfc9421Bridge` memetakan header SecurePayload ke `Signature-Input` / `Signature` / `Content-Digest` (algoritma bridge: **hmac-sha256**), dan sebaliknya memvalidasi digest lalu mendelegasikan ke `SecurePayload::verify()`. Bridge **bukan** pengganti wire SecurePayload.

```php
use SecurePayload\Interop\Rfc9421Bridge;

[$spHeaders, $body] = $client->buildHeadersAndBody($url, 'POST', $payload);
$rfcHeaders = Rfc9421Bridge::exportFromSecureHeaders($spHeaders, 'POST', '/v1/resource', 'limit=10', $body);
// $rfcHeaders berisi Signature-Input, Signature, Content-Digest (+ header SP yang relevan)

$result = Rfc9421Bridge::verifyMapped($server, $rfcHeaders, $body, 'POST', '/v1/resource', 'limit=10');
```

Dokumentasi: [`docs/RFC9421_BRIDGE.md`](docs/RFC9421_BRIDGE.md). Contoh: [`examples/interop/rfc9421.php`](examples/interop/rfc9421.php).

---

## ⚙️ Opsi Konstruktor

| Opsi            | Tipe       | Default  | Keterangan                                                              |
| :-------------- | :--------- | :------- | :---------------------------------------------------------------------- |
| `mode`          | string     | `both`   | `hmac` \| `aead` \| `both`.                                            |
| `signAlg`       | string     | `hmac`   | `hmac` \| `ed25519` \| `hybrid-mldsa44-ed25519`.                       |
| `version`       | string     | `4`      | Versi protokol; client & server harus sama. Gunakan `'3'` untuk v3.   |
| `clientId`      | string     | —        | Wajib di sisi client.                                                  |
| `keyId`         | string     | —        | Wajib di sisi client.                                                  |
| `hmacSecretRaw` | string     | —        | Secret HMAC mentah, **≥ 32 karakter** (signAlg=hmac).                  |
| `ed25519SecretKeyB64` | string | —     | Secret key Ed25519 base64 64-byte (client, signAlg=ed25519/hybrid).   |
| `ed25519PublicKeyServerB64` | string | — | Public key Ed25519 server (client, verifikasi response).            |
| `ed25519SecretKeyServerB64` | string | — | Secret key Ed25519 server (server, signing response).               |
| `mldsaSecretKeyB64` / `mldsaPublicKeyB64` | string | — | Kunci ML-DSA client (signAlg hybrid).                    |
| `mldsaSecretKeyServerB64` / `mldsaPublicKeyServerB64` | string | — | Kunci ML-DSA server (response hybrid).         |
| `pqSigner`      | object     | —        | `PqSignerInterface`; **wajib** jika `signAlg` hybrid.                  |
| `aeadKeyB64`    | string     | —        | Kunci AEAD base64, decode **tepat 32 byte**.                           |
| `keyLoader`     | callable   | —        | `fn($cid, $kid): array{...}` (server; termasuk field Ed25519/ML-DSA). |
| `replayStore`   | callable   | —        | `fn(string $key, int $ttl): bool` — store nonce terpusat (lihat di bawah). |
| `replayTtl`     | int        | `120`    | Masa berlaku nonce (detik).                                            |
| `clockSkew`     | int        | `60`     | Toleransi selisih jam (detik).                                         |
| `bindHeaders`   | string[]   | `[]`     | Nama header kritikal yang diikat ke AAD AEAD; harus sama di client & server. |
| `deriveKeys`    | bool       | `false`  | Master key → subkey HKDF per-fungsi; harus sama di client & server.   |
| `onSecurityEvent` | callable | —        | Hook observasional untuk SIEM/rate-limiter (context tanpa secret).   |
| `httpTransport` | object\|callable | — | `HttpTransportInterface` atau factory untuk `send()`/`sendFile()`. |

---

## 🔁 Anti-Replay di Lingkungan Multi-Server

Cache nonce **bawaan berbasis file** (`sys_get_temp_dir()`) **tidak terbagi** antar server/worker di belakang load balancer. Untuk produksi multi-server, **wajib** inject `replayStore` yang didukung Redis/Memcached:

```php
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);

$server = new SecurePayload([
    'mode'        => 'both',
    'keyLoader'   => $loader,
    'replayStore' => function (string $key, int $ttl) use ($redis): bool {
        // SET NX: true jika nonce baru, false jika sudah pernah dipakai (replay)
        return (bool) $redis->set($key, '1', ['nx', 'ex' => $ttl]);
    },
]);
```

### Adapter PSR-16 bawaan (`Psr16ReplayStore`)

Bila aplikasi sudah punya cache **PSR-16** (`Psr\SimpleCache\CacheInterface`), pakai adapter bawaan alih-alih menulis closure sendiri:

```php
use SecurePayload\ReplayStore\Psr16ReplayStore;

$server = new SecurePayload([
    'mode'        => 'both',
    'keyLoader'   => $loader,
    'replayStore' => new Psr16ReplayStore($cache), // invokable → cocok sebagai callable
]);
```

> ⚠️ **Atomicity:** PSR-16 inti tidak punya primitif *set-if-not-exists*. Adapter memakai `add()` atomik bila cache menyediakannya, atau jatuh ke `has()+set()` (best-effort) untuk PSR-16 murni — ada jendela balapan kecil pada konkurensi tinggi. Untuk jaminan ketat, gunakan store dengan primitif atomik native (Redis `SET NX` / Memcached `add`). Lihat `examples/replay-store/`. Tambahkan `composer require psr/simple-cache` (dependensi opsional).

---

## 🔐 Manajemen Kunci (KMS)

### Provider dari Environment

`EnvKeyProvider` membaca variabel `SECUREPAYLOAD_{CID}_{KID}_HMAC_SECRET`, `SECUREPAYLOAD_{CID}_{KID}_AEAD_KEY_B64`, dan `SECUREPAYLOAD_{CID}_{KID}_ED25519_PUBLIC_B64`:

```php
use SecurePayload\KMS\EnvKeyProvider;

$provider = new EnvKeyProvider();
$keys = $provider->load('client_001', 'key_v1');
// ['hmacSecret' => ..., 'aeadKeyB64' => ...]
```

### Provider dari Database (PDO)

`DbKeyProvider` membaca dari tabel `secure_keys` (nama tabel/kolom bisa dikonfigurasi). Bila baris menyimpan kunci AEAD ter-*wrap*, kunci akan di-*unwrap* otomatis lewat `Kms` yang diinject:

```php
use SecurePayload\KMS\DbKeyProvider;
use SecurePayload\KMS\LocalKms;

$provider = new DbKeyProvider($pdo, [], LocalKms::fromEnv());
$server   = new SecurePayload([
    'mode'      => 'both',
    'keyLoader' => fn($cid, $kid) => $provider->load($cid, $kid),
]);
```

### Membangkitkan & Membungkus Kunci (Key-Wrapping)

```php
use SecurePayload\KMS\KeyManager;
use SecurePayload\KMS\LocalKms;

$kms     = LocalKms::fromEnv();              // KEK dari env (SECURE_KEKS + SECURE_KEK_{id}_B64)
$manager = new KeyManager($kms);

$result = $manager->generateKeyPair('client_002', 'key_v1', 'master_kek_id');

echo $result->toSqlInsert('secure_keys');    // INSERT SQL siap pakai (kolom AEAD plaintext di-null-kan)
```

### KMS Terkelola (Cloud) — Vault & AWS

`LocalKms` cocok untuk dev. Untuk produksi, tersedia adapter `Kms` berbasis penyedia terkelola. Keduanya menjaga kontrak AAD context (`['client_id','key_id','purpose']`) — dipetakan ke mekanisme *encryption context* native penyedia — dan **tidak mengubah format wire**, hanya cara kunci di-*wrap/unwrap*.

```php
use SecurePayload\KMS\VaultKms;
use SecurePayload\KMS\AwsKms;

// HashiCorp Vault — Transit engine. AAD → parameter `context` Transit.
// Kunci Transit WAJIB dibuat dengan derived=true:  vault write -f transit/keys/<kekId> derived=true
$kms = new VaultKms('https://vault.example.com:8200', getenv('VAULT_TOKEN') ?: '');

// AWS KMS — AAD → EncryptionContext. Bungkus Aws\Kms\KmsClient (composer require aws/aws-sdk-php).
$client = new \Aws\Kms\KmsClient(['region' => 'ap-southeast-1', 'version' => 'latest']);
$kms = new AwsKms($client);

// GCP Cloud KMS — AAD → additionalAuthenticatedData (composer suggest google/cloud-kms).
$kms = new \SecurePayload\KMS\GcpKms($gcpKmsClient);

// Azure Key Vault — AAD → additionalAuthenticatedData (composer suggest azure/keyvault-keys).
$kms = new \SecurePayload\KMS\AzureKeyVaultKms($cryptoClient);

// Pakai sama seperti LocalKms (inject ke DbKeyProvider / KeyManager):
$provider = new \SecurePayload\KMS\DbKeyProvider($pdo, [], $kms);
```

> `VaultKms` memakai token auth + Transit; transport HTTP dapat di-inject (default cURL, butuh `ext-curl`). `AwsKms` membungkus klien `Aws\Kms\KmsClient` (dependensi opsional). `GcpKms` dan `AzureKeyVaultKms` mengikuti pola injeksi klien yang sama (unit-testable tanpa jaringan). Kredensial cloud mengikuti rantai standar SDK masing-masing.

---

## 📂 Contoh Integrasi Framework

Implementasi lengkap (middleware client & server) tersedia di folder [`examples/`](examples/EXAMPLES.md):

| Framework        | Path                                | Isi                                   |
| :--------------- | :---------------------------------- | :------------------------------------ |
| **CodeIgniter 4**| [`examples/ci4/`](examples/ci4/)       | Filter & Library Client               |
| **Laravel**      | [`examples/laravel/`](examples/laravel/) | Middleware & service berbasis Http    |
| **Lumen**        | [`examples/lumen/`](examples/lumen/)   | Middleware & wrapper Guzzle           |
| **Slim 4**       | [`examples/slim/`](examples/slim/)     | PSR-15 Middleware & PSR-18 Client     |
| **Symfony**      | [`examples/symfony/`](examples/symfony/) | Event Subscriber & HttpClient Service |
| **Native PHP**   | [`examples/native/`](examples/native/) | Implementasi tanpa framework          |
| **Webhook**      | [`examples/webhook/`](examples/webhook/) | `WebhookVerifier` + raw body        |

### SDK Node.js & Go

| SDK | Path | Catatan |
| :-- | :--- | :------ |
| **Node / TypeScript** | [`packages/node-sdk`](packages/node-sdk/) | API mirror PHP; middleware Express & plugin Fastify (`@sk8dvlpr/securepayload-node/express`, `.../fastify`). Wajib raw body sebelum verify. |
| **Go** | [`packages/go-sdk`](packages/go-sdk/) | API mirror PHP; middleware Gin / Echo / Fiber di package `middleware`. |

Deployment mTLS (transport) bersama SecurePayload (aplikasi): [`docs/MTLS_DEPLOYMENT.md`](docs/MTLS_DEPLOYMENT.md).

---

## 🧪 Pengembangan

```bash
composer install                       # pasang dependensi dev
composer test                          # jalankan seluruh suite PHPUnit
vendor/bin/phpunit --testsuite Security  # jalankan satu suite
composer stan                          # PHPStan level 5 pada src/
```

---

## 📡 Header Keamanan

| Header                  | Fungsi                                              |
| :---------------------- | :-------------------------------------------------- |
| `X-Client-Id`           | Identitas client.                                   |
| `X-Key-Id`              | ID kunci yang dipakai.                              |
| `X-Timestamp`           | Waktu request (validasi kesegaran).                 |
| `X-Nonce`               | Token unik sekali-pakai (anti-replay).              |
| `X-Signature`           | Nilai tanda tangan (HMAC / Ed25519 / hybrid).       |
| `X-Signature-Version`   | Versi protokol (`4` default; atau `3`).             |
| `X-Signature-Algorithm` | `HMAC-SHA256`, `ED25519`, atau `HYBRID-MLDSA44-ED25519`. |
| `X-Body-Digest`         | Digest SHA-256 dari body (`sha256=...`).            |
| `X-Canonical-Request`   | Petunjuk debug — **bukan** sumber kebenaran server. |
| `X-AEAD-Algorithm`      | Algoritma enkripsi (`XCHACHA20-POLY1305-IETF`).     |
| `X-AEAD-Nonce`          | Nonce AEAD yang terikat konteks request.            |
| `X-SP-Multipart`        | `1` bila body adalah multipart file stream.         |
| `X-Resp-*`              | Padanan header di atas untuk **response** (timestamp, nonce, signature, body-digest, AEAD), terikat ke nonce request asal. |

---

## 📄 Lisensi

Open-source di bawah lisensi **MIT**. Silakan gunakan dan modifikasi sesuai kebutuhan proyek Anda.
