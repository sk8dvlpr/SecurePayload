<?php
declare(strict_types=1);

/**
 * Contoh replay-store ATOMIK berbasis Memcached (ekstensi memcached).
 *
 * Cocok untuk produksi multi-server: semua worker berbagi satu cluster Memcached.
 *
 * Kunci keamanan: pakai `add()` — bukan `set()`. `Memcached::add()` hanya
 * berhasil bila key BELUM ada (set-if-not-exists) dan bersifat atomik di sisi
 * server Memcached, sehingga dua request dengan nonce sama yang tiba bersamaan
 * dijamin: satu menang, sisanya ditolak.
 *   - Return true  → key baru dibuat (nonce lolos).
 *   - Return false → key sudah ada (replay terdeteksi).
 * Argumen ke-3 add() adalah expiration (detik) → key kedaluwarsa otomatis.
 */

use SecurePayload\SecurePayload;

$mc = new Memcached();
$mc->addServer('127.0.0.1', 11211);

$replayStore = function (string $cacheKey, int $ttl) use ($mc): bool {
    // true  → nonce BARU (lolos); false → replay.
    return $mc->add($cacheKey, '1', max(1, $ttl));
};

$server = new SecurePayload([
    'mode' => 'both',
    'replayStore' => $replayStore, // <-- titik ekstensi
    'keyLoader' => function (string $cid, string $kid): array {
        return ['hmacSecret' => getenv('SP_HMAC') ?: '', 'aeadKeyB64' => getenv('SP_AEAD_B64') ?: null];
    },
]);

// $result = $server->verify($headers, $rawBody, $method, $path, $query);
