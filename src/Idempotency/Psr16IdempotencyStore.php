<?php

declare(strict_types=1);

namespace SecurePayload\Idempotency;

use Psr\SimpleCache\CacheInterface;
use Throwable;

/**
 * Adapter store idempotensi berbasis PSR-16 (SimpleCache).
 *
 * Memungkinkan aplikasi memakai backend cache apa pun yang mengimplementasikan
 * PSR-16 (Redis, Memcached, APCu, dsb.) sebagai penyimpan hasil idempotensi,
 * melalui kontrak {@see IdempotencyStoreInterface}. Setiap kunci diberi prefiks
 * namespace agar beberapa aplikasi yang berbagi satu cache tidak saling
 * menimpa entri.
 *
 * Fail-closed pada pembacaan: nilai cache yang bukan array (korup/tipe salah)
 * dianggap sebagai miss — tidak pernah dikembalikan ke pemanggil.
 */
final class Psr16IdempotencyStore implements IdempotencyStoreInterface
{
    /** Prefiks namespace bawaan untuk semua kunci cache. */
    public const DEFAULT_PREFIX = 'sp-idem-';

    private CacheInterface $cache;
    private string $prefix;

    /**
     * @param CacheInterface $cache Backend cache PSR-16.
     * @param string         $prefix Prefiks namespace kunci (harus non-kosong).
     */
    public function __construct(CacheInterface $cache, string $prefix = self::DEFAULT_PREFIX)
    {
        if ($prefix === '') {
            throw new \InvalidArgumentException('Prefiks idempotensi tidak boleh kosong.');
        }
        $this->cache = $cache;
        $this->prefix = $prefix;
    }

    /**
     * Ambil hasil eksekusi tersimpan. Nilai korup/non-array dianggap miss.
     */
    public function get(string $key): ?array
    {
        try {
            $value = $this->cache->get($this->prefix . $key);
        } catch (Throwable $e) {
            // Kegagalan backend cache dianggap miss — pola idempotensi tidak
            // boleh menggagalkan request hanya karena cache sedang tidak sehat.
            return null;
        }
        return is_array($value) ? $value : null;
    }

    /**
     * Simpan hasil eksekusi. TTL <= 0 dipetakan ke null (tanpa kedaluwarsa
     * menurut semantik PSR-16). Kegagalan backend ditelan: idempotensi adalah
     * optimalisasi keandalan — request utama tetap berjalan tanpanya.
     */
    public function set(string $key, array $result, int $ttl): void
    {
        try {
            $this->cache->set($this->prefix . $key, $result, $ttl > 0 ? $ttl : null);
        } catch (Throwable $e) {
            // Sengaja diabaikan — lihat docblock kelas.
        }
    }
}
