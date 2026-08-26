<?php

declare(strict_types=1);

namespace SecurePayload\Idempotency;

/**
 * Store idempotensi in-memory .
 *
 * Cocok untuk development, test, dan proses single-worker. Data HILANG saat
 * proses mati dan TIDAK dibagi antar server — untuk produksi multi-server
 * pakai Psr16IdempotencyStore di atas Redis/Memcached.
 *
 * Semantik kedaluwarsa: lazy — entri kedaluwarsa baru dibuang saat di-get.
 */
final class ArrayIdempotencyStore implements IdempotencyStoreInterface
{
    /** @var array<string,array{expiresAt:int,result:array<string,mixed>}> Map kunci → entri; expiresAt 0 = tanpa batas. */
    private array $items = [];

    public function get(string $key): ?array
    {
        if (!isset($this->items[$key])) {
            return null;
        }
        $entry = $this->items[$key];
        if ($entry['expiresAt'] !== 0 && $entry['expiresAt'] <= time()) {
            unset($this->items[$key]);
            return null;
        }
        return $entry['result'];
    }

    public function set(string $key, array $result, int $ttl): void
    {
        $this->items[$key] = [
            'expiresAt' => $ttl > 0 ? time() + $ttl : 0,
            'result' => $result,
        ];
    }
}
