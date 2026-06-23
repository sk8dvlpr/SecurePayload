# Dokumentasi Contoh Integrasi SecurePayload

Folder ini berisi contoh implementasi library **SecurePayload** di berbagai framework PHP populer dan Native PHP. Setiap sub-folder mencakup contoh kode untuk dua sisi komunikasi:

1.  **PENERIMA (Server/Receiver)**: Middleware atau Filter untuk memvalidasi request yang masuk.
2.  **PENGIRIM (Client/Sender)**: Service atau Helper untuk mengirim request aman ke server.

---

## 1. CodeIgniter 4 (`examples/ci4/`)

CodeIgniter 4 menggunakan sistem **Filters** untuk middleware.

*   **Penerima**: `SecurePayloadFilter.php`
    *   Mengimplementasikan `CodeIgniter\Filters\FilterInterface`.
    *   Mencegat request di method `before()`, memvalidasi header security, dan menolak request (400/401) jika tanda tangan tidak valid.
*   **Pengirim**: `SecurePayloadClient.php`
    *   Contoh Library wrapper yang menggunakan `CURLRequest` (Service HTTP Client CI4).
    *   Method `sendSecurePost()` otomatis membungkus data dengan enkripsi dan tanda tangan sebelum dikirim.

---

## 2. Laravel (`examples/laravel/`)

Laravel menggunakan **Middleware** standar.

*   **Penerima**: `SecurePayloadMiddleware.php`
    *   Middleware global atau route-specific.
    *   Menggunakan `EnvKeyProvider` (atau `DbKeyProvider`) untuk memuat kunci rahasia berdasarkan `X-Client-Id` header.
    *   Hasil verifikasi (termasuk body JSON yang didekripsi) disimpan ke `$request->attributes`.
*   **Pengirim**: `SecurePayloadService.php`
    *   Service class yang menggunakan facade `Illuminate\Support\Facades\Http`.
    *   Menunjukkan cara mengambil config dari `config/services.php` dan mengirim request aman.

---

## 3. Lumen (`examples/lumen/`)

Mirip dengan Laravel namun dioptimalkan untuk microservices.

*   **Penerima**: `SecurePayloadMiddleware.php` (Sama dengan versi Laravel tapi disesuaikan untuk Object Request Lumen).
*   **Pengirim**: `SecurePayloadService.php`
    *   Menggunakan `GuzzleHttp\Client` secara langsung karena Lumen sering digunakan tanpa Facade.
    *   Menangani penggabungan Base URL untuk canonicalization path yang akurat.

---

## 4. Slim 4 (`examples/slim/`)

Framework mikro berbasis standar PSR-7 dan PSR-15.

*   **Penerima**: `SecurePayloadMiddleware.php`
    *   Middleware `__invoke` yang murni PSR-15.
    *   Memvalidasi objek `ServerRequestInterface` dan mengembalikan `ResponseInterface`.
*   **Pengirim**: `SecurePayloadClient.php`
    *   Class wrapper yang menerima `GuzzleHttp\ClientInterface` (Dependency Injection).
    *   Menunjukkan cara bersih memisahkan logic security dari logic HTTP transport.

---

## 5. Symfony (`examples/symfony/`)

Menggunakan Event Subscriber untuk performa dan fleksibilitas di Kernel Events.

*   **Penerima**: `SecurePayloadSubscriber.php`
    *   Mendengarkan event `kernel.request` dengan prioritas tinggi.
    *   Memvalidasi request sebelum Controller dieksekusi.
    *   Mengembalikan `JsonResponse` error langsung dari event jika validasi gagal.
*   **Pengirim**: `SecurePayloadService.php`
    *   Menggunakan komponen `Symfony\Contracts\HttpClient\HttpClientInterface`.
    *   Service yang siap di-inject ke Controller atau Service lain (Dependency Injection Container ready).

---

## 6. Native PHP (`examples/native/`)

Untuk proyek legacy atau skrip sederhana tanpa framework.

*   **Penerima**: `index.php`
    *   Menunjukkan cara membaca `php://input` dan `$_SERVER` manual.
    *   Memparse header HTTP secara manual untuk kompatibilitas server (Apache/Nginx/FPM).
*   **Pengirim**: `sender.php`
    *   Contoh penggunaan ekstensi `curl` (raw cURL) untuk mengirim request.
    *   Menunjukkan langkah manual konversi header array ke format string cURL.

---

## 7. File Upload

Fitur baru di v1.3.0 untuk mengirim file secara aman (Encrypted + Signed).

*   **Penerima (Receiver)**: Menggunakan method `verifyFilePayload()` untuk memvalidasi ukuran, ekstensi (termasuk deteksi MIME spoofing), dan integritas file.
*   **Pengirim (Sender)**: Menggunakan helper `sendFile()` untuk kemudahan pengiriman.
*   **Contoh File**:
    *   **Native**: `examples/native/upload_sender.php` & `examples/native/upload_receiver.php`
    *   **CI4**: `examples/ci4/UploadController.php`
    *   **Laravel**: `examples/laravel/UploadController.php`
    *   **Lumen**: `examples/lumen/UploadController.php`
    *   **Slim**: `examples/slim/upload_routes.php`
    *   **Symfony**: `examples/symfony/UploadController.php`

---

## Transfer File Besar — Streaming AEAD (`examples/file-stream/`)

Untuk file besar, gunakan API streaming (`buildFileStream()` / `verifyFileStream()`) yang memproses file **per-chunk** via XChaCha20-Poly1305 *secretstream* — tanpa memuat seluruh file ke RAM.

*   **Pengirim**: `examples/file-stream/stream_sender.php` — enkripsi streaming → manifest (dikirim via request aman) + file ciphertext (diunggah terpisah).
*   **Penerima**: `examples/file-stream/stream_receiver.php` — verifikasi manifest, lalu `verifyFileStream()` mendekripsi + memvalidasi (ukuran, ekstensi, strict MIME). Gagal-tertutup: plaintext parsial dihapus bila gagal.

> Pemakaian RAM ≈ satu chunk (default 64 KiB; disarankan 256 KiB–1 MiB untuk file besar). Proteksi truncation/append (TAG_FINAL) + digest ciphertext aktif.

---

## Replay Store untuk Multi-Server (`examples/replay-store/`)

Cache nonce **bawaan berbasis file** tidak terbagi antar server/worker. Untuk produksi multi-server, inject `replayStore` yang terpusat. Tiga contoh siap pakai:

*   **Redis (atomik)**: `examples/replay-store/redis.php` — `SET key val NX EX ttl`.
*   **Memcached (atomik)**: `examples/replay-store/memcached.php` — `Memcached::add()`.
*   **PSR-16 (adapter bawaan)**: `examples/replay-store/psr16.php` — `Psr16ReplayStore` membungkus cache PSR-16 milik aplikasi.

> **Atomicity**: untuk bebas race-condition, operasi "tandai-jika-belum-ada" harus atomik. Redis (`SET NX`) dan Memcached (`add`) menyediakannya secara native. PSR-16 inti tidak — adapter memakai jalur best-effort kecuali cache yang dibungkus mengekspos `add()`.

---

## Catatan Keamanan (Penting)

1.  **Mode Operasi**: Sebagian besar contoh menggunakan mode `'both'` (Signature + Encryption) karena ini yang paling aman. Pastikan kedua belah pihak (Client & Server) memiliki konfigurasi mode yang sama.
2.  **Key Provider**: Contoh-contoh ini menggunakan `EnvKeyProvider` demi kesederhanaan. Untuk produksi dengan banyak client, disarankan menggunakan `DbKeyProvider` (Database) dan menyimpan kunci dengan aman.
3.  **HTTPS**: SecurePayload mengamankan *payload* (body) dan integritas request, tapi **wajib** menggunakan HTTPS (TLS) untuk mengamankan jalur transport itu sendiri.
