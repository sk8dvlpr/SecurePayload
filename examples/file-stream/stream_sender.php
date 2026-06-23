<?php
declare(strict_types=1);

/**
 * Contoh PENGIRIM transfer file streaming (Phase 6) — untuk file besar.
 *
 * Pola:
 *   1. Enkripsi file per-chunk ke file ciphertext (tanpa memuat seluruh file ke RAM).
 *   2. `buildFileStream()` mengembalikan MANIFEST kecil (metadata + header + digest).
 *   3. Kirim MANIFEST lewat jalur request aman biasa (ditandatangani/enkripsi).
 *   4. Unggah file ciphertext secara terpisah (mis. multipart / PUT biner).
 *
 * Server memverifikasi manifest, lalu memanggil `verifyFileStream()` atas ciphertext.
 */

use SecurePayload\SecurePayload;

$sp = new SecurePayload([
    'mode' => 'both',
    'clientId' => 'c1',
    'keyId' => 'k1',
    'hmacSecretRaw' => getenv('SP_HMAC') ?: str_repeat('x', 32),
    'aeadKeyB64' => getenv('SP_AEAD_B64') ?: base64_encode(str_repeat('k', 32)),
    // 'deriveKeys' => true, // opsional: subkey HKDF per-fungsi (harus sama di server)
]);

$srcPath = '/path/ke/file-besar.zip';
$cipherPath = sys_get_temp_dir() . '/upload.sps'; // ciphertext sementara

// 1+2: enkripsi streaming → manifest. chunkSize 64KiB–1MiB direkomendasikan.
$manifest = $sp->buildFileStream($srcPath, $cipherPath, ['name' => basename($srcPath)], 256 * 1024);

// 3: kirim manifest sebagai payload request aman (manifest = sumber kebenaran integritas).
[$headers, $body] = $sp->buildHeadersAndBody('https://api.example.com/upload/manifest', 'POST', $manifest);
// ... kirim $headers + $body via cURL/HTTP client Anda ...

// 4: unggah file ciphertext ($cipherPath) terpisah, mis. multipart ke /upload/blob.
//    Server mencocokkannya dengan manifest yang sudah diverifikasi.

echo "Manifest siap dikirim. Ciphertext: $cipherPath (" . filesize($cipherPath) . " bytes)\n";
