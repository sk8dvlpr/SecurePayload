# Implementation Plan — SecurePayload

> Rencana pengembangan untuk menjaga SecurePayload tetap relevan dan optimal menghadapi ancaman keamanan modern.
> Disusun per-phase berdasarkan **prioritas dampak keamanan** dan **tingkat kompleksitas**.

## Ringkasan & Prinsip

Fondasi kripto library ini (XChaCha20-Poly1305 + HMAC-SHA256) masih merupakan *best practice*. Pengembangan di bawah **tidak mengganti** primitif tersebut, melainkan menutup celah pada **model kepercayaan** dan **cakupan proteksi**.

Prinsip yang dipegang selama implementasi:

- **Backward-compatible** — fitur baru ditambahkan sebagai opsi/mode, bukan mengubah perilaku default. Perubahan format wire **wajib** menaikkan `version` protokol.
- **Aman secara default** — opsi baru tidak boleh melemahkan jaminan yang sudah ada (jangan buka jalur downgrade).
- **Konsistensi gaya** — `declare(strict_types=1)`, class `final`, komentar/docblock/pesan exception dalam **Bahasa Indonesia**, kompatibel PHP 8.0.
- **Setiap perubahan signing/verifying wajib mempertahankan invarian keamanan** yang tercatat di `CLAUDE.md` (canonicalization simetris, server menurunkan method/path/query dari input sendiri, dst).
- **Tiap phase disertai test** di suite yang sesuai (`Unit` / `Integration` / `Security`).

---

## Phase 1 — Signing Asimetris (Ed25519) 🔴 Prioritas Tertinggi ✅ SELESAI (v2.0.0)

**Masalah:** HMAC bersifat simetris — server menyimpan secret yang sama dengan yang dipakai client untuk menandatangani. Akibatnya server **bisa memalsukan** request atas nama client, dan kebocoran DB kunci server membocorkan identitas semua client. Tidak ada *non-repudiation*.

**Solusi:** Tambahkan mode signing asimetris berbasis `sodium_crypto_sign` (Ed25519). Client memegang *private key*, server cukup memegang *public key*.

### Tugas
- [ ] Tambah mode/opsi signing baru (mis. `signAlg: 'hmac' | 'ed25519'`), dengan `HMAC-SHA256` tetap default.
- [ ] Konstanta header & algoritma baru (`X-Signature-Algorithm: ED25519`).
- [ ] Sisi client: pakai `ed25519PrivateKeyB64`; tandatangani `hmacMessage()` yang sudah ada via `sodium_crypto_sign_detached()`.
- [ ] Sisi server: `keyLoader` mengembalikan `ed25519PublicKeyB64`; verifikasi via `sodium_crypto_sign_verify_detached()`.
- [ ] Validasi panjang key (public 32 byte, secret 64 byte) saat konstruksi & saat dimuat dari `keyLoader`.
- [ ] Perluas `KeyManager` untuk membangkitkan pasangan Ed25519 (`sodium_crypto_sign_keypair`) dan `GeneratedKeyResult::toSqlInsert()`.
- [ ] `EnvKeyProvider` / `DbKeyProvider` mendukung kolom/var public-key baru.

### Pertimbangan
- **Naikkan `version`** protokol karena algoritma signing berubah.
- Pertahankan invarian: server tetap menurunkan method/path/query dari input sendiri; pesan kanonik tidak berubah.
- Guard di balik `ensureSodium()` (sama seperti AEAD).
- Test: signing/verify happy path, penolakan signature palsu, penolakan key salah panjang (`Security` suite).

---

## Phase 2 — Pengamanan Response (Two-Way Integrity) 🔴 Prioritas Tinggi ✅ SELESAI (v2.1.0)

**Masalah:** Library hanya mengamankan **request**. Client tidak bisa memverifikasi bahwa response benar berasal dari server asli dan tidak dimodifikasi di tengah jalan.

**Solusi:** Tambahkan mekanisme sign/encrypt untuk response, simetris dengan jalur request.

### Tugas
- [ ] Sisi server: `buildResponse(array $payload, ...)` yang menghasilkan header + body terproteksi (mengikat ke nonce/konteks request agar response tidak bisa dipindah ke request lain).
- [ ] Sisi client: `verifyResponse(array $headers, string $body, ...)`.
- [ ] Bind response ke request (mis. sertakan `X-Nonce` request ke dalam pesan kanonik response) untuk mencegah *response replay/relocation*.
- [ ] Dukung semua mode (`hmac`/`aead`/`both`) konsisten dengan jalur request.

### Pertimbangan
- Reuse helper yang sudah ada (`hmacMessage`, `aeadNonceFrom`, `bodyDigestB64`) agar logika tetap simetris.
- Test: round-trip request→response, penolakan response yang dimodifikasi, penolakan response yang dipindah konteks (`Integration` + `Security`).

---

## Phase 3 — Binding Timestamp & Header Kritikal ke AAD 🟠 Prioritas Menengah ✅ SELESAI (v2.2.0)

**Masalah:** Pada mode `aead`, `X-Timestamp` tidak terotentikasi. Saat ini sudah dimitigasi (replay key sengaja mengecualikan timestamp), tetapi manipulasi timestamp/header lain tidak langsung menggagalkan dekripsi.

**Solusi:** Ikat timestamp (dan opsional header kritikal seperti `Content-Type`) ke dalam **AAD** AEAD, sehingga perubahannya otomatis menggagalkan dekripsi.

### Tugas
- [x] Perluas `aeadAAD()` agar menyertakan timestamp + daftar header yang dipilih (urutan deterministik / `ksort`).
- [x] Pastikan client & server membangun AAD secara identik.
- [x] Opsi konfigurasi `bindHeaders: string[]` untuk header tambahan yang ingin diikat.
- [x] Bonus: timestamp response (`X-Resp-Timestamp`) juga diikat ke AAD response (simetris dengan request).

### Pertimbangan
- **Naikkan `version`** karena AAD berubah → ciphertext lama tidak akan terdekripsi (memang diinginkan, tidak ada cross-version).
- Jaga agar mode `hmac`-only (tanpa sodium) tetap berjalan tanpa perubahan.
- Test: dekripsi gagal saat timestamp/header diubah (`Security` suite).

---

## Phase 4 — Replay Store Siap Pakai (PSR-16) 🟠 Prioritas Menengah ✅ SELESAI (v2.3.0)

**Masalah:** Default replay store berbasis file tidak terbagi antar server/worker. Sudah didokumentasikan, tetapi mudah terlupa diganti di produksi.

**Solusi:** Sediakan adapter siap pakai berbasis **PSR-16 `SimpleCache`**, plus contoh Redis, agar jalur aman lebih mudah diadopsi.

### Tugas
- [x] Adapter `Psr16ReplayStore` yang membungkus cache PSR-16 menjadi callable `fn(string $key, int $ttl): bool` (atomic, mis. `add()`/`SET NX`).
- [x] Contoh konkret Redis & Memcached di `examples/` (`examples/replay-store/`).
- [x] Dokumentasikan jaminan atomicity yang dibutuhkan agar bebas race-condition.
- [x] Adapter mendeteksi jalur atomik (`add()`) vs best-effort; `isAtomic()` untuk diagnostik (alih-alih log peringatan global).

### Pertimbangan
- `psr/simple-cache` ditambahkan sebagai `suggest`/optional dependency, bukan wajib.
- Pertahankan titik ekstensi `replayStore` yang sudah ada; ini hanya implementasi tambahan.
- Test: deteksi replay lintas-instance dengan mock PSR-16 (`Integration`).

---

## Phase 5 — Derivasi Subkey via HKDF 🟡 Prioritas Pendukung ✅ SELESAI (v2.4.0)

**Masalah:** Satu kunci dipakai langsung untuk satu fungsi. Pemisahan domain antar fungsi (enkripsi vs signing vs response) bisa diperkuat.

**Solusi:** Turunkan *subkey per-purpose* dari satu master key menggunakan `hash_hkdf()`, sehingga kompromi satu subkey tidak meruntuhkan fungsi lain.

### Tugas
- [x] Helper `deriveKey(string $master, string $purpose): string` berbasis `hash_hkdf('sha256', ...)` (publik & teruji).
- [x] Pakai `info`/`purpose` berbeda untuk: enkripsi request, enkripsi response, signing request, signing response (`sp-aead-req`, `sp-aead-resp`, `sp-sign-req`, `sp-sign-resp`).
- [x] Mode opsional `deriveKeys` (default false) agar pengguna lama yang memasok kunci langsung tetap didukung.

### Pertimbangan
- `ext-hash` sudah menjadi dependency wajib — `hash_hkdf` tersedia di PHP 7.1.3+.
- Karena `deriveKeys` *opt-in* (default off → wire byte-identik dengan v3), `version` **tidak** dinaikkan paksa; sebagai gantinya label `info` HKDF diikat ke versi protokol dan konfigurasi wajib sinkron di kedua sisi (gagal-tertutup bila tidak cocok). Signing Ed25519 tidak diturunkan (sudah asimetris).

---

## Phase 6 — Streaming AEAD untuk File Besar 🟡 Prioritas Pendukung ✅ SELESAI (v2.5.0)

**Masalah:** `buildFilePayload()` memuat seluruh file ke RAM lalu base64 (+33% overhead) — tidak cocok untuk file besar (sudah ada `@warning` di kode).

**Solusi:** Tambahkan jalur transfer file berbasis `sodium_crypto_secretstream_xchacha20poly1305_*` (enkripsi per-chunk, tanpa memuat seluruh file).

### Tugas
- [x] API baru `buildFileStream()` / `verifyFileStream()` yang memproses file per-chunk (secretstream).
- [x] Pertahankan validasi keamanan file yang sudah ada (size limit, ext allow/block, `strict_mime` magic-byte sniffing) — diekstrak jadi helper bersama.
- [x] Dokumentasikan batas memori & rekomendasi ukuran chunk (README + `examples/file-stream/`).

### Pertimbangan
- Format payload berbeda dari `_attachment` base64 → API terpisah (manifest + file ciphertext), bukan mengubah yang lama.
- Sniffing MIME pada stream membaca 1 KiB pertama chunk pertama yang sudah didekripsi.
- Bonus keamanan: proteksi truncation/append (TAG_FINAL tunggal & wajib), digest ciphertext diikat ke manifest yang ditandatangani, dan **gagal-tertutup** (plaintext parsial dihapus saat gagal).
- Test: round-trip (multi-chunk, kelipatan tepat, file kosong, `deriveKeys`) + penolakan chunk rusak/truncation/append/digest/kunci salah/spoof MIME/ekstensi (`Integration` + `Security`).

---

## Phase 7 — Adapter Cloud KMS 🟢 Prioritas Lanjutan ✅ SELESAI (v2.6.0)

**Masalah:** `LocalKms` cocok untuk dev, tetapi produksi idealnya memakai KMS terkelola.

**Solusi:** Implementasi `Kms` interface (yang sudah ada: `wrap()`/`unwrap()`) untuk penyedia eksternal.

### Tugas
- [x] Adapter `VaultKms` (HashiCorp Vault Transit) **dan** `AwsKms` (AWS KMS).
- [x] Pertahankan kontrak AAD context (`['client_id', 'key_id', 'purpose']`) → dipetakan ke `context` (Vault) / `EncryptionContext` (AWS), konsisten dengan `LocalKms`.
- [x] Dokumentasi konfigurasi kredensial cloud (README + composer `suggest`).

### Pertimbangan
- Dependency SDK cloud bersifat opsional (`suggest` `aws/aws-sdk-php`), tidak masuk core. `VaultKms` memakai transport HTTP injectable (default cURL) — tanpa SDK.
- Tidak mengubah format wire — hanya cara kunci di-*wrap/unwrap* di server.
- Test: round-trip wrap→unwrap, penolakan AAD/context yang berbeda, propagasi error HTTP — semua via mock (tanpa jaringan) di suite `Unit`.

---

## Phase 8 — Observability & Audit Hooks 🟢 Prioritas Lanjutan ✅ SELESAI (v2.7.0)

**Masalah:** Tidak ada cara terstruktur untuk memantau event keamanan (replay terdeteksi, signature gagal) ke SIEM / rate-limiter.

**Solusi:** Tambahkan hook event opsional pada titik-titik keamanan.

### Tugas
- [x] Opsi callback `onSecurityEvent: fn(string $event, array $context): void`.
- [x] Emit event pada: replay terdeteksi, signature invalid, dekripsi gagal, timestamp di luar batas, key tidak ditemukan, dan nonce mismatch (bonus). Tersedia sebagai konstanta `SecurePayload::EVENT_*`.
- [x] Pastikan context **tidak membocorkan** material rahasia — diuji eksplisit (tidak ada secret/plaintext).

### Pertimbangan
- Murni aditif, tidak mengubah perilaku verifikasi. Exception dari callback ditelan agar observability tidak pernah memengaruhi keamanan.
- Test: event terpanggil pada tiap skenario gagal yang relevan + callback exception ditelan + tidak ada event saat sukses (`Unit`).

---

## Urutan Eksekusi yang Disarankan

| Urutan | Phase | Alasan |
| :----: | :---- | :----- |
| 1 | Phase 1 (Ed25519) | Dampak keamanan terbesar (model kepercayaan). |
| 2 | Phase 2 (Response) | Menutup celah cakupan paling kentara (integritas dua arah). |
| 3 | Phase 4 (PSR-16) | Effort rendah, langsung mengurangi misconfig produksi. |
| 4 | Phase 3 (AAD binding) | Memperkuat mode `aead`; bisa digabung saat menaikkan `version`. |
| 5 | Phase 5 (HKDF) | Pendukung; sebaiknya satu paket dengan kenaikan `version`. |
| 6 | Phase 6 (Streaming) | Fitur baru terpisah, tidak memblok lainnya. |
| 7 | Phase 7 (Cloud KMS) | Aditif, tergantung kebutuhan deployment. |
| 8 | Phase 8 (Observability) | Aditif, bisa kapan saja. |

> **Catatan versi protokol:** Phase 1, 3, dan 5 mengubah format wire. Sebaiknya dikelompokkan agar kenaikan `version` (mis. `1` → `2`) terjadi sekali dan terdokumentasi di `CHANGELOG.md`.
