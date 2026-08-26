<?php
declare(strict_types=1);

namespace SecurePayload\Storage\Adapter;

use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\Storage\StorageAdapterInterface;

/**
 * Adapter penyimpanan blob berbasis filesystem lokal.
 *
 * Key divalidasi ketat terhadap regex ^[a-f0-9]{32}$ (fail-closed anti
 * path traversal) dan dipetakan langsung ke satu file flat di bawah
 * $rootDir — tidak ada subdirektori yang bisa disusupi dari key.
 * Penulisan atomik: tulis ke file sementara di direktori yang sama,
 * lalu rename ke nama akhir agar pembaca tidak pernah melihat isi
 * setengah jadi.
 */
final class LocalStorageAdapter implements StorageAdapterInterface
{
    /** Pola key file_id: 32 karakter hex lowercase (D2/D7). */
    private const KEY_PATTERN = '/^[a-f0-9]{32}$/';

    private string $rootDir;

    /** Permission file blob hasil put() (default 0660). */
    private int $fileMode;

    /**
     * @param array{dirMode?:int,fileMode?:int} $opts
     *        dirMode  : mode mkdir rekursif (default 0770).
     *        fileMode : mode chmod file blob setelah rename (default 0660).
     *
     * @throws SecurePayloadException Bila direktori gagal dibuat/bukan direktori/tak writable,
     *                                atau opsi mode tidak valid.
     */
    public function __construct(string $rootDir, array $opts = [])
    {
        if ($rootDir === '') {
            throw new SecurePayloadException('rootDir tidak boleh kosong', SecurePayloadException::BAD_REQUEST);
        }
        $dirMode = $opts['dirMode'] ?? 0770;
        if (!is_int($dirMode) || $dirMode <= 0) {
            throw new SecurePayloadException('dirMode wajib bertipe integer oktal positif', SecurePayloadException::BAD_REQUEST);
        }
        $fileMode = $opts['fileMode'] ?? 0660;
        if (!is_int($fileMode) || $fileMode <= 0) {
            throw new SecurePayloadException('fileMode wajib bertipe integer oktal positif', SecurePayloadException::BAD_REQUEST);
        }
        if (!is_dir($rootDir) && !@mkdir($rootDir, $dirMode, true) && !is_dir($rootDir)) {
            throw new SecurePayloadException("Gagal membuat direktori penyimpanan: $rootDir", SecurePayloadException::SERVER_ERROR);
        }
        if (!is_dir($rootDir)) {
            throw new SecurePayloadException("Path penyimpanan bukan direktori: $rootDir", SecurePayloadException::SERVER_ERROR);
        }
        if (!is_writable($rootDir)) {
            throw new SecurePayloadException("Direktori penyimpanan tidak dapat ditulis: $rootDir", SecurePayloadException::SERVER_ERROR);
        }
        // Normalisasi pemisah agar penggabungan path aman lintas OS.
        $this->rootDir = rtrim($rootDir, '/\\');
        $this->fileMode = $fileMode;
    }

    /**
     * Validasi key dan kembalikan path file absolutnya.
     *
     * @throws SecurePayloadException BAD_REQUEST bila key tidak sesuai pola.
     */
    private function resolvePath(string $key): string
    {
        if (preg_match(self::KEY_PATTERN, $key) !== 1) {
            throw new SecurePayloadException(
                'Key penyimpanan tidak valid (harus 32 karakter hex lowercase)',
                SecurePayloadException::BAD_REQUEST
            );
        }
        return $this->rootDir . DIRECTORY_SEPARATOR . $key;
    }

    public function put(string $key, string $contents): void
    {
        $path = $this->resolvePath($key);
        // Tmp di direktori yang sama supaya rename bersifat atomik (satu filesystem).
        $tmp = $path . '.tmp-' . bin2hex(random_bytes(8));
        try {
            if (@file_put_contents($tmp, $contents, LOCK_EX) === false) {
                throw new SecurePayloadException("Gagal menulis blob sementara: $key", SecurePayloadException::SERVER_ERROR);
            }
            if (!@rename($tmp, $path)) {
                throw new SecurePayloadException("Gagal memindahkan blob ke lokasi akhir: $key", SecurePayloadException::SERVER_ERROR);
            }
            // Permission file eksplisit (default 0660). Kegagalan chmod pada filesystem
            // yang tidak mendukung diabaikan — tidak boleh menggagalkan put().
            @chmod($path, $this->fileMode);
        } finally {
            // Jangan tinggalkan file sementara bila rename gagal.
            if (is_file($tmp)) {
                @unlink($tmp);
            }
        }
    }

    public function get(string $key): string
    {
        $path = $this->resolvePath($key);
        if (!is_file($path)) {
            throw new SecurePayloadException("Blob tidak ditemukan: $key", SecurePayloadException::BAD_REQUEST);
        }
        $contents = @file_get_contents($path);
        if ($contents === false) {
            throw new SecurePayloadException("Gagal membaca blob: $key", SecurePayloadException::SERVER_ERROR);
        }
        return $contents;
    }

    public function delete(string $key): void
    {
        $path = $this->resolvePath($key);
        // Toleransi no-op: unlink false karena file memang sudah tidak ada
        // dianggap sukses (idempoten); gagal saat file masih ada tetap error.
        if (!@unlink($path) && is_file($path)) {
            throw new SecurePayloadException("Gagal menghapus blob: $key", SecurePayloadException::SERVER_ERROR);
        }
    }

    public function exists(string $key): bool
    {
        $path = $this->resolvePath($key);
        return is_file($path) && is_readable($path);
    }
}
