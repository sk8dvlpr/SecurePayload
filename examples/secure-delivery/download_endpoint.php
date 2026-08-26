<?php
declare(strict_types=1);

/**
 * Contoh ENDPOINT DOWNLOAD aman (Secure Delivery) — PHP native.
 *
 * Pola broker (WAJIB — jangan pernah ekspos path/blob Storage langsung):
 *   1. Aplikasi menerbitkan URL ber-token (Bagian A, mode CLI --issue).
 *   2. Endpoint memverifikasi token → pasang header keamanan → retrieveStream() (Bagian B).
 *
 * Watermark forensik demo: jalankan dengan env SP_WATERMARK=1 untuk menyisipkan
 * baris lisensi identitas pemegang ke payload sebelum di-stream (fail-closed —
 * hook gagal = respons dibatalkan). Untuk PDF nyata pasang mpdf/mpdf.
 *
 * Coba:
 *   # Terminal 1: terbitkan URL untuk sebuah file
 *   php examples/secure-delivery/download_endpoint.php --issue /path/ke/dokumen.pdf
 *
 *   # Terminal 2: jalankan web server lalu buka URL yang dicetak di atas
 *   SP_WATERMARK=1 php -S localhost:8080 examples/secure-delivery/download_endpoint.php
 */

use SecurePayload\Delivery\SecureLinkIssuer;
use SecurePayload\Delivery\SecureLinkVerifier;
use SecurePayload\KMS\LocalKms;
use SecurePayload\Storage\Adapter\LocalStorageAdapter;
use SecurePayload\Storage\FileManifest;
use SecurePayload\Storage\SecureFileStorage;

require __DIR__ . '/../../vendor/autoload.php';

// Secret bersama Issuer & Verifier — minimal 32 karakter (rekomendasi 64 byte hex).
$hmacSecret  = getenv('SP_LINK_SECRET') ?: str_repeat('s', 32); // PRODUKSI: set env sungguhan
$blobDir     = sys_get_temp_dir() . '/securepayload-example-blobs';
$manifestDir = sys_get_temp_dir() . '/securepayload-example-manifests';

// "DB" manifest mini: satu file JSON per file_id — ganti dengan repositori DB aplikasi Anda.
function find_manifest(string $dir, string $fileId): ?FileManifest
{
    $f = $dir . '/' . $fileId . '.json';
    return is_file($f)
        ? FileManifest::fromArray(json_decode((string) file_get_contents($f), true))
        : null;
}

function save_manifest(string $dir, FileManifest $m): void
{
    if (!is_dir($dir)) {
        mkdir($dir, 0770, true);
    }
    file_put_contents($dir . '/' . $m->fileId() . '.json', json_encode($m->toArray()));
}

function build_storage(string $blobDir): SecureFileStorage
{
    // Fallback KEK dev DETERMINISTIK agar blob tetap terbuka lintas proses
    // (CLI --issue → web server). Produksi wajib pakai env/secret manager sungguhan.
    if (getenv('SECURE_KEKS') === false) {
        putenv('SECURE_KEKS=DEMOKEK');
        putenv('SECURE_KEK_DEMOKEK_B64=' . base64_encode(hash('sha256', 'securepayload-demo-kek', true)));
    }
    return new SecureFileStorage(LocalKms::fromEnv(), new LocalStorageAdapter($blobDir), [
        'onSecurityEvent' => static function (string $event, array $ctx): void {
            error_log('[secure-delivery] ' . $event . ' ' . json_encode($ctx)); // audit non-secret
        },
    ]);
}

/* ================================================================
 * Bagian A — PENERBITAN TOKEN (mode CLI).
 * Di aplikasi nyata ini hidup di controller report/upload Anda,
 * BUKAN di endpoint publik.
 * ================================================================ */
if (PHP_SAPI === 'cli') {
    if (($argv[1] ?? '') !== '--issue' || !isset($argv[2])) {
        fwrite(STDERR, "Pemakaian: php download_endpoint.php --issue <path-file>\n");
        exit(1);
    }
    $src = $argv[2];
    if (!is_file($src)) {
        fwrite(STDERR, "File tidak ditemukan: {$src}\n");
        exit(1);
    }

    $storage  = build_storage($blobDir);
    $manifest = $storage->store($src, ['client_id' => 'report-service', 'kek_id' => 'DEMOKEK']);
    save_manifest($manifestDir, $manifest);

    // singleUse=false untuk demo tanpa Redis. Untuk sekali-pakai: set SP_LINK_SINGLE_USE=1
    // dan pastikan replayStore tersedia (lihat Bagian B) — tanpa store token su DITOLAK fail-closed.
    $singleUse = getenv('SP_LINK_SINGLE_USE') === '1';
    $issuer    = new SecureLinkIssuer($hmacSecret);
    $token     = $issuer->issue($manifest->fileId(), ttl: 300, singleUse: $singleUse);

    echo "URL unduhan (berlaku 5 menit):\n";
    echo "http://localhost:8080/download_endpoint.php?file={$manifest->fileId()}&token={$token}\n";
    echo "file_id : {$manifest->fileId()}\n";
    exit(0);
}

/* ================================================================
 * Bagian B — ENDPOINT DOWNLOAD (broker).
 * ================================================================ */

$fileId = $_GET['file'] ?? '';
$token  = $_GET['token'] ?? '';
if (!is_string($fileId) || $fileId === '' || !is_string($token) || $token === '') {
    http_response_code(400);
    exit('Parameter file dan token wajib ada.');
}

// replayStore untuk token sekali-pakai: fn(cacheKey, ttl): bool — pola sama dgn protokol utama.
// TANPA store, semua token single-use DITOLAK (replay_store_required — fail-closed).
$replayStore = null;
if (extension_loaded('redis')) {
    try {
        $redis = new Redis();
        $redis->connect(getenv('SP_REDIS_HOST') ?: '127.0.0.1', (int) (getenv('SP_REDIS_PORT') ?: 6379));
        $replayStore = static fn(string $key, int $ttl): bool
            => (bool) $redis->set($key, '1', ['nx', 'ex' => $ttl]);   // SET NX = atomik
    } catch (Throwable) {
        // fall-through: tanpa store → token single-use ditolak, token multi-use tetap sah.
    }
}

$verifier = new SecureLinkVerifier($hmacSecret, $replayStore);

// boundTo: identitas pemegang sesi saat ini (mis. client id login). Null jika token tak terikat.
$boundTo = null;
$check   = $verifier->verify($fileId, $token, $boundTo);
if (!$check['ok']) {
    http_response_code(403);
    exit('Akses ditolak: ' . $check['error']);       // alasan singkat: format_token, token_expired, dll.
}

// Hook watermark forensik (opsional, level aplikasi) — aktif via SP_WATERMARK=1.
// Kontrak: beforeStream(plaintext, manifest, ctx): string dipanggil TEPAT 1x
// SEBELUM chunk pertama; exception/return non-string = streaming dibatalkan.
$streamOpts = [];
if (getenv('SP_WATERMARK') === '1') {
    $claims    = $check['claims'] ?? [];
    $requester = [
        'subject' => (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown'),
        'jti'     => (string) ($claims['jti'] ?? ''),
    ];
    if (class_exists('\Mpdf\Mpdf')) {
        // PDF nyata? Di sinilah stamp mpdf dijalankan (composer require mpdf/mpdf):
        // render ulang / tempel watermark per halaman lalu kembalikan byte-nya.
        // Demo ini tetap memakai watermark TEKS sederhana agar bebas dependensi.
    }
    $streamOpts = [
        'requester' => $requester,
        'beforeStream' => static function (string $plain, FileManifest $m, array $ctx): string {
            $who = (string) ($ctx['requester']['subject'] ?? 'unknown');
            return "-- Lisensi unduhan: {$who} | file={$ctx['file_id']} --\n" . $plain;
        },
    ];
}

try {
    $storage  = build_storage($blobDir);
    $manifest = find_manifest($manifestDir, $fileId);
    if ($manifest === null || !$storage->exists($manifest)) {
        http_response_code(404);
        exit('File tidak ditemukan.');
    }

    // Header keamanan respons — WAJIB sebelum output apa pun:
    // CATATAN: Content-Length sengaja TIDAK diset — saat watermark aktif ukuran
    // final body baru diketahui setelah hook jalan; biarkan transfer chunked.
    $safeName = preg_replace('/[^A-Za-z0-9._-]/', '_', $manifest->metadata()['nama_asli'] ?? $manifest->fileId());
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $safeName . '"');
    header('Cache-Control: no-store, no-cache, must-revalidate');   // respons unduhan tidak boleh dicache
    header('X-Content-Type-Options: nosniff');

    // Sink: closure biasa (bukan arrow fn void) — print mengembalikan int,
    // dan fn():void => print tidak valid di PHP (void tidak boleh return nilai).
    $storage->retrieveStream($manifest, static function (string $chunk): void {
        print $chunk;
    }, $streamOpts);
} catch (Throwable $e) {
    // Fail-closed: jangan bocorkan detail internal (KMS/AEAD) ke client.
    error_log('[secure-delivery] stream gagal: ' . $e->getMessage());
    if (!headers_sent()) {
        http_response_code(500);
    }
    exit('Gagal membuka file.');
}
