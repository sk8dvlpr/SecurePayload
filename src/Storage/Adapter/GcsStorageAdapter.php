<?php
declare(strict_types=1);

namespace SecurePayload\Storage\Adapter;

use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\Storage\StorageAdapterInterface;
use Throwable;

/**
 * Adapter penyimpanan blob ciphertext berbasis Google Cloud Storage (GCS).
 *
 * Mengimplementasikan {@see StorageAdapterInterface} dengan membungkus objek
 * bucket — biasanya `Google\Cloud\Storage\Bucket` dari `google/cloud-storage`
 * (dependency OPSIONAL, lihat `suggest`). Bucket di-*duck-type*: cukup
 * memiliki method `upload(string, array)` dan `object(string)`; objek hasilnya
 * cukup memiliki `downloadAsString()`, `exists()`, dan `delete()`.
 *
 * Key blob selalu divalidasi regex `[a-f0-9]{32}` (fail-closed anti path
 * traversal), konsisten dengan LocalStorageAdapter.
 *
 * Contoh wiring:
 *
 *     $storageClient = new \Google\Cloud\Storage\StorageClient();
 *     $adapter = new GcsStorageAdapter($storageClient->bucket('secure-files'));
 *     $storage = new SecureFileStorage(LocalKms::fromEnv(), $adapter);
 */
final class GcsStorageAdapter implements StorageAdapterInterface
{
    private const KEY_PATTERN = '/^[a-f0-9]{32}$/';

    private object $bucket;

    /**
     * @param object $bucketClient Objek bucket GCS (duck-typed).
     */
    public function __construct(object $bucketClient, array $opts = [])
    {
        unset($opts); // Disimpan demi keseragaman signature; tidak ada opsi tambahan saat ini.
        if (!is_callable([$bucketClient, 'upload']) || !is_callable([$bucketClient, 'object'])) {
            throw new SecurePayloadException(
                'Klien GCS harus memiliki method upload() dan object()',
                SecurePayloadException::BAD_REQUEST
            );
        }
        $this->bucket = $bucketClient;
    }

    public function put(string $key, string $contents): void
    {
        self::assertKey($key);
        try {
            call_user_func([$this->bucket, 'upload'], $contents, ['name' => $key]);
        } catch (Throwable $e) {
            throw self::wrap($e, "gagal menyimpan blob '$key'");
        }
    }

    public function get(string $key): string
    {
        self::assertKey($key);
        try {
            /** @var mixed $obj */
            $obj = call_user_func([$this->bucket, 'object'], $key);
            if (!is_object($obj) || !is_callable([$obj, 'downloadAsString'])) {
                throw new SecurePayloadException(
                    "respons object('$key') tidak memiliki downloadAsString()",
                    SecurePayloadException::SERVER_ERROR
                );
            }
            $out = call_user_func([$obj, 'downloadAsString']);
        } catch (Throwable $e) {
            throw self::wrap($e, "gagal membaca blob '$key'");
        }
        // Semantik konsisten dengan Local/S3: kembalikan SELURUH isi blob apa adanya.
        // Blob ciphertext storage selalu >= header+frame sehingga blob kosong tak dikecualikan.
        if (!is_string($out)) {
            throw new SecurePayloadException(
                "GcsStorageAdapter: isi blob '$key' bukan string pada respons",
                SecurePayloadException::SERVER_ERROR
            );
        }
        return $out;
    }

    public function delete(string $key): void
    {
        self::assertKey($key);
        try {
            /** @var mixed $obj */
            $obj = call_user_func([$this->bucket, 'object'], $key);
            if (!is_object($obj) || !is_callable([$obj, 'delete'])) {
                throw new SecurePayloadException(
                    "respons object('$key') tidak memiliki delete()",
                    SecurePayloadException::SERVER_ERROR
                );
            }
            call_user_func([$obj, 'delete']);
        } catch (Throwable $e) {
            throw self::wrap($e, "gagal menghapus blob '$key'");
        }
    }

    public function exists(string $key): bool
    {
        self::assertKey($key);
        try {
            /** @var mixed $obj */
            $obj = call_user_func([$this->bucket, 'object'], $key);
            if (!is_object($obj) || !is_callable([$obj, 'exists'])) {
                throw new SecurePayloadException(
                    "respons object('$key') tidak memiliki exists()",
                    SecurePayloadException::SERVER_ERROR
                );
            }
            /** @var mixed $res */
            $res = call_user_func([$obj, 'exists']);
        } catch (Throwable $e) {
            throw self::wrap($e, "gagal memeriksa keberadaan blob '$key'");
        }
        return (bool) $res;
    }

    /**
     * Validasi key fail-closed: harus hex lowercase tepat 32 karakter.
     */
    private static function assertKey(string $key): void
    {
        if (preg_match(self::KEY_PATTERN, $key) !== 1) {
            throw new SecurePayloadException('GcsStorageAdapter: key tidak valid', SecurePayloadException::BAD_REQUEST);
        }
    }

    /**
     * Bungkus error SDK dengan konteks operasi Indonesia (chain previous tetap terjaga).
     */
    private static function wrap(Throwable $e, string $action): SecurePayloadException
    {
        return new SecurePayloadException(
            'GcsStorageAdapter: ' . $action . ': ' . $e->getMessage(),
            SecurePayloadException::SERVER_ERROR,
            [],
            $e
        );
    }
}
