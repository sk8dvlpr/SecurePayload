<?php
declare(strict_types=1);

/**
 * Contoh replay-store ATOMIK berbasis Redis (ekstensi phpredis).
 *
 * Cocok untuk produksi multi-server: semua worker berbagi satu Redis, sehingga
 * nonce yang sudah dipakai di satu server langsung terlihat oleh server lain.
 *
 * Kunci keamanan: pakai `SET key val NX EX ttl` — operasi TUNGGAL yang atomik.
 *   - NX  : hanya set bila key BELUM ada (set-if-not-exists).
 *   - EX  : kedaluwarsa otomatis setelah `ttl` detik (mencegah penumpukan key).
 * Return Redis::set() bernilai true bila key baru dibuat (nonce lolos),
 * false bila key sudah ada (replay terdeteksi).
 */

use SecurePayload\SecurePayload;

$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
// $redis->auth('password'); // bila perlu

$replayStore = function (string $cacheKey, int $ttl) use ($redis): bool {
    // true  → nonce BARU (lolos)
    // false → nonce sudah dipakai (replay)
    return (bool) $redis->set($cacheKey, '1', ['nx', 'ex' => max(1, $ttl)]);
};

$server = new SecurePayload([
    'mode' => 'both',
    'replayStore' => $replayStore, // <-- titik ekstensi
    'keyLoader' => function (string $cid, string $kid): array {
        // ...muat kunci per-(clientId, keyId) Anda di sini...
        return ['hmacSecret' => getenv('SP_HMAC') ?: '', 'aeadKeyB64' => getenv('SP_AEAD_B64') ?: null];
    },
]);

// $result = $server->verify($headers, $rawBody, $method, $path, $query);
