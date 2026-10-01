<?php
declare(strict_types=1);

namespace SecurePayload\ReplayStore;

use InvalidArgumentException;
use Psr\SimpleCache\CacheInterface;

/**
 * Adapter replay-store berbasis PSR-16 (SimpleCache).
 *
 * Membungkus implementasi `Psr\SimpleCache\CacheInterface` apa pun menjadi
 * callable yang cocok dengan opsi `replayStore` SecurePayload:
 *
 *     $store  = new Psr16ReplayStore($psr16cache, true); // wajib atomic add()
 *     $server = new SecurePayload(['mode' => 'both', 'replayStore' => $store, ...]);
 *
 * Kontrak callable: `fn(string $cacheKey, int $ttl): bool` — mengembalikan
 * `true` bila nonce BARU (belum pernah dipakai), `false` bila replay terdeteksi.
 *
 * ## Jaminan atomicity (WAJIB dibaca untuk produksi multi-server)
 *
 * Agar BEBAS race-condition, operasi "tandai-jika-belum-ada" harus **atomik**.
 * PSR-16 inti TIDAK menyediakan primitif atomik semacam itu (`set-if-not-exists`),
 * sehingga adapter ini memakai dua jalur:
 *
 *  1. **Jalur atomik** — bila cache yang dibungkus mengekspos method `add()`
 *     (umum pada pembungkus Memcached), adapter memakainya. `add()` hanya
 *     berhasil bila key belum ada, jadi dua request dengan nonce sama yang
 *     tiba bersamaan dijamin: satu menang, sisanya ditolak.
 *
 *  2. **Jalur best-effort** — PSR-16 murni (`has()` lalu `set()`). Praktis untuk
 *     mayoritas kasus, NAMUN ada jendela balapan sangat kecil. Untuk produksi
 *     high-concurrency, set `$requireAtomic = true` (gagal saat construct bila
 *     `add()` tidak tersedia) atau pakai Redis `SET NX EX` — lihat `examples/`.
 *
 * Implementasi PSR-16 yang dipakai HARUS menghormati TTL agar key replay
 * kedaluwarsa otomatis (mencegah penumpukan key tak terbatas).
 */
final class Psr16ReplayStore
{
    private CacheInterface $cache;

    /** @var bool Apakah cache yang dibungkus menyediakan add() atomik. */
    private bool $hasAtomicAdd;

    public function __construct(CacheInterface $cache, bool $requireAtomic = false)
    {
        $this->cache = $cache;
        $this->hasAtomicAdd = is_callable([$cache, 'add']);
        if ($requireAtomic && !$this->hasAtomicAdd) {
            throw new InvalidArgumentException(
                'Psr16ReplayStore requireAtomic=true tetapi cache tidak mengekspos add() atomik'
            );
        }
    }

    /**
     * Tandai nonce sebagai terpakai.
     *
     * @param string $cacheKey Kunci replay yang sudah di-hash oleh SecurePayload.
     * @param int    $ttl      Lama key harus diingat (detik).
     *
     * @return bool true jika nonce baru (lolos), false jika replay terdeteksi.
     */
    public function __invoke(string $cacheKey, int $ttl): bool
    {
        // Jalur atomik (set-if-not-exists). add() mengembalikan true hanya bila
        // key BARU dibuat, sehingga bebas race-condition.
        if ($this->hasAtomicAdd) {
            return (bool) call_user_func([$this->cache, 'add'], $cacheKey, '1', $ttl);
        }

        // Jalur best-effort: PSR-16 murni tidak punya add() atomik.
        if ($this->cache->has($cacheKey)) {
            return false;
        }
        $this->cache->set($cacheKey, '1', $ttl);
        return true;
    }

    /**
     * Apakah adapter memakai jalur atomik (add()) untuk store yang dibungkus.
     * Berguna untuk logging/diagnostik di lingkungan produksi.
     */
    public function isAtomic(): bool
    {
        return $this->hasAtomicAdd;
    }
}
