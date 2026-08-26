<?php
declare(strict_types=1);

namespace SecurePayload\Storage;

use SecurePayload\Exceptions\SecurePayloadException;

/**
 * Kontrak adapter penyimpanan blob ciphertext untuk SecureFileStorage.
 *
 * Adapter bersifat string-based dan flat: key selalu nama logis blob
 * (32 karakter hex lowercase, lihat validasi key), bukan path bebas.
 * Implementasi WAJIB fail-closed: key yang tidak lolos validasi harus
 * ditolak dengan SecurePayloadException (BAD_REQUEST) untuk mencegah
 * path traversal.
 */
interface StorageAdapterInterface
{
    /**
     * Simpan $contents secara atomik di bawah $key (menimpa isi lama).
     *
     * @throws SecurePayloadException Jika key tidak valid atau penulisan gagal.
     */
    public function put(string $key, string $contents): void;

    /**
     * Ambil seluruh isi blob pada $key.
     *
     * @throws SecurePayloadException Jika key tidak valid atau blob tidak ada/gagal dibaca.
     */
    public function get(string $key): string;

    /**
     * Hapus blob pada $key. File yang sudah tidak ada dianggap no-op;
     * kegagalan hapus saat file masih ada tetap melempar exception.
     *
     * @throws SecurePayloadException Jika key tidak valid atau penghapusan gagal.
     */
    public function delete(string $key): void;

    /**
     * Cek keberadaan (dan keterbacaan) blob pada $key.
     *
     * @throws SecurePayloadException Jika key tidak valid.
     */
    public function exists(string $key): bool;
}
