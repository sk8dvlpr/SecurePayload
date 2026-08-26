<?php

declare(strict_types=1);

namespace SecurePayload\Idempotency;

/**
 * Kontrak store idempotensi — TERPISAH dari anti-replay.
 *
 * Beda tujuan dengan ReplayStore:
 *  - anti-replay MENOLAK nonce yang dipakai ulang (keamanan);
 *  - idempotency MENGIZINKAN retry yang sah dan mengembalikan hasil response
 *    yang sama tanpa efek ganda (keandalan bisnis, mis. order/pembayaran).
 *
 * Fitur ini sengaja TIDAK digabung ke RequestVerifier — pemanggil aplikasi yang
 * memutuskan eksekusi ulang vs balas dari cache, memakai kunci dari header
 * X-Idempotency-Key.
 */
interface IdempotencyStoreInterface
{
    /**
     * Ambil hasil eksekusi tersimpan untuk kunci idempotensi.
     *
     * @param string $key Kunci idempotensi (mis. isi header X-Idempotency-Key
     *                    yang sudah dinormalisasi/dinamespace oleh implementasi).
     *
     * @return array<string,mixed>|null Hasil tersimpan, atau null bila belum ada/kedaluwarsa.
     */
    public function get(string $key): ?array;

    /**
     * Simpan hasil eksekusi untuk kunci idempotensi.
     *
     * @param string $key Kunci idempotensi.
     * @param array<string,mixed> $result Hasil eksekusi; JANGAN menyimpan data rahasia.
     * @param int $ttl Lama simpan dalam detik; nilai <= 0 berarti tanpa kedaluwarsa.
     */
    public function set(string $key, array $result, int $ttl): void;
}
