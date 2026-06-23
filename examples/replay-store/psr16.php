<?php
declare(strict_types=1);

/**
 * Contoh replay-store memakai adapter PSR-16 bawaan: Psr16ReplayStore.
 *
 * Pakai ini bila aplikasi Anda sudah punya cache PSR-16 (Symfony Cache, Laravel
 * `cache()->store()`, php-cache, dll) dan ingin memakainya kembali untuk replay
 * protection tanpa menulis closure sendiri.
 *
 *   composer require psr/simple-cache   # + implementasi PSR-16 pilihan Anda
 *
 * ⚠️ Atomicity: PSR-16 inti TIDAK punya primitif set-if-not-exists. Adapter ini:
 *   - memakai add() ATOMIK bila cache yang dibungkus menyediakannya
 *     (umum pada pembungkus Memcached), atau
 *   - jatuh ke has()+set() (best-effort) untuk PSR-16 murni — ada jendela
 *     balapan sangat kecil pada konkurensi tinggi.
 * Untuk jaminan ketat di lingkungan high-concurrency, pakai store dengan
 * primitif atomik native — lihat `redis.php` (SET NX) atau `memcached.php` (add).
 */

use SecurePayload\ReplayStore\Psr16ReplayStore;
use SecurePayload\SecurePayload;

/** @var \Psr\SimpleCache\CacheInterface $cache  Cache PSR-16 milik aplikasi Anda. */
$cache = /* ...ambil instance PSR-16 Anda... */ null;

$replayStore = new Psr16ReplayStore($cache);

// Opsional: cek apakah jalur atomik aktif (berguna untuk logging produksi).
// if (!$replayStore->isAtomic()) { /* warn: best-effort, pertimbangkan Redis/Memcached */ }

$server = new SecurePayload([
    'mode' => 'both',
    'replayStore' => $replayStore, // Psr16ReplayStore bersifat invokable → cocok sebagai callable
    'keyLoader' => function (string $cid, string $kid): array {
        return ['hmacSecret' => getenv('SP_HMAC') ?: '', 'aeadKeyB64' => getenv('SP_AEAD_B64') ?: null];
    },
]);

// $result = $server->verify($headers, $rawBody, $method, $path, $query);
