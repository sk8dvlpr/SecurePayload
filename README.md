# SecurePayload

> **The Ultimate Secure Request Library for PHP**
>
> Amankan komunikasi antar-server (S2S) atau Client-Server dengan mudah menggunakan standar kriptografi modern: **HMAC-SHA256** dan **AEAD (XChaCha20-Poly1305)**.

[![CI](https://img.shields.io/github/actions/workflow/status/sk8dvlpr/securepayload/ci.yml?branch=main&label=CI&style=flat-square)]()
[![PHP Version](https://img.shields.io/badge/php-%E2%89%A5%208.0-blue?style=flat-square)]()
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)]()
[![Packagist Version](https://img.shields.io/packagist/v/sk8dvlpr/securepayload.svg?style=flat-square)](https://packagist.org/packages/sk8dvlpr/securepayload)

**SecurePayload** adalah library PHP _all-in-one_ yang dirancang untuk mengatasi kompleksitas pengamanan API. Dengan satu class, Anda dapat menandatangani (Sign), mengenkripsi (Encrypt), dan memvalidasi request HTTP dengan perlindungan anti-replay attack yang ketat.

---

## 🌟 Fitur Utama

-   **Dual Security Mode**:
    -   `HMAC`: Integritas data terjamin (Tanda tangan digital).
    -   `AEAD`: Integritas + Kerahasiaan (Enkripsi penuh).
    -   `BOTH`: Kombinasi keduanya untuk keamanan maksimal.
-   **Anti-Replay Attack**: Proteksi otomatis menggunakan Timestamp dan Nonce Cache.
-   **Secure File Transfer**: Kirim file dengan aman (terenkripsi & tertanda-tangan) termasuk validasi ketat (MIME-Type & Extension).
-   **Zero Configuration**: Verifikasi cerdas yang mendeteksi algoritma secara otomatis.
-   **Key Management System (KMS)**: Dukungan bawaan untuk rotasi kunci dan enkripsi kunci database (Key Wrapping).
-   **Framework Agnostic**: Siap pakai untuk Laravel, CodeIgniter 4, Symfony, Slim, Lumen, dan Native PHP.

---

## 📦 Instalasi

Install library via Composer:

```bash
composer require sk8dvlpr/securepayload
```

> **Requirements**:
> - PHP 8.0 atau lebih baru.
> - Ekstensi `sodium` (wajib untuk mode AEAD/BOTH).
> - Ekstensi `curl` (opsional, untuk helper client).

---

## 🚀 Cara Kerja

SecurePayload bekerja dengan menyisipkan header keamanan standar industri ke dalam request HTTP Anda:

1.  **Sender (Pengirim)**: Library akan melakukan canonicalization request, membuat hash (HMAC), dan mengenerate token unik (Nonce). Jika mode AEAD aktif, body request juga akan dienkripsi.
2.  **Transmisi**: Request dikirim dengan header tambahan seperti `X-Signature`, `X-Timestamp`, `X-Nonce`, dll.
3.  **Receiver (Penerima)**: Library memvalidasi timestamp (mencegah request kadaluarsa), mengecek nonce (mencegah replay), dan memverifikasi tanda tangan kriptografi.

---

## 📖 Quick Start

### 1. Sisi Client (Pengirim Request)

```php
use SecurePayload\SecurePayload;

// Inisialisasi dengan kredensial client
$client = new SecurePayload([
    'mode'          => 'both', // Encrypt + Sign
    'clientId'      => 'client_001',
    'keyId'         => 'key_v1',
    'hmacSecretRaw' => hex2bin('af9...'), // 32 bytes raw binary
    'aeadKeyB64'    => 'base64key...',    // 32 bytes base64
]);

$targetUrl = 'https://api.tujuan.com/v1/resource';
$payload   = ['user_id' => 123, 'action' => 'debit'];

// Generate Header Aman & Body Terenkripsi
[$headers, $secureBody] = $client->buildHeadersAndBody($targetUrl, 'POST', $payload);

// Kirim menggunakan HTTP Client favorit Anda (Guzzle, CURL, dll)
// ...
```

### 2. Sisi Server (Penerima Request)

```php
use SecurePayload\SecurePayload;
use SecurePayload\KMS\EnvKeyProvider;

// Setup Provider Kunci (Bisa dari ENV atau Database)
$provider = new EnvKeyProvider();
$loader   = fn($cid, $kid) => $provider->load($cid, $kid);

$server = new SecurePayload([
    'mode'      => 'both',
    'keyLoader' => $loader
]);

// Verifikasi Request Masuk
$result = $server->verify(
    getallheaders(),           // Array Header
    file_get_contents('php://input'), // Raw Body
    $_SERVER['REQUEST_METHOD'],
    parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH)
);

if (!$result['ok']) {
    http_response_code(401);
    die(json_encode(['error' => $result['error']]));
}

// Sukses! Data aman tersedia di $result['json']
$data = $result['json']; 
```

---

## 📂 Contoh Integrasi Framework

Kami menyediakan contoh implementasi lengkap (Middleware & Service) untuk berbagai framework populer di dalam folder [`examples/`](examples/EXAMPLES.md):

| Framework | Path | Deskripsi |
| :--- | :--- | :--- |
| **CodeIgniter 4** | [`examples/ci4/`](examples/ci4/) | Filter & Library Client |
| **Laravel** | [`examples/laravel/`](examples/laravel/) | Middleware & Http Facade Service |
| **Lumen** | [`examples/lumen/`](examples/lumen/) | Middleware & Guzzle Wrapper |
| **Slim 4** | [`examples/slim/`](examples/slim/) | PSR-15 Middleware & PSR-18 Client |
| **Symfony** | [`examples/symfony/`](examples/symfony/) | Event Subscriber & HttpClient Service |
| **Native PHP** | [`examples/native/`](examples/native/) | Implementasi tanpa framework |

Silakan baca [**Dokumentasi Examples**](examples/EXAMPLES.md) untuk detail lengkap cara penggunaannya.

---

## 🔐 Manajemen Kunci (Key Management)

Untuk aplikasi skala besar (Multi-Client), disarankan menggunakan **Database Key Provider**. SecurePayload menyediakan utility `KeyManager` untuk mempermudah ini.

### Membuat Kunci Baru (dengan Enkripsi KMS)

```php
use SecurePayload\KMS\KeyManager;
use SecurePayload\KMS\LocalKms;

// 1. Setup KMS (Master Key Wrapper)
$kms = LocalKms::fromEnv();

// 2. Generate Kunci untuk Client Baru
$manager = new KeyManager($kms);
$creds   = $manager->generateKeyPair('client_002', 'key_v1', 'master_kek_id');

// 3. Dapatkan Query SQL untuk insert ke DB
echo $creds->toSqlInsert('secure_keys');
// Output: INSERT INTO `secure_keys` ...
```

---

## 📄 Lisensi

Library ini bersifat open-source di bawah lisensi **MIT**. Silakan gunakan dan modifikasi sesuai kebutuhan proyek Anda.
