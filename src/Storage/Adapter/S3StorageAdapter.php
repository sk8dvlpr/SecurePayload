<?php
declare(strict_types=1);

namespace SecurePayload\Storage\Adapter;

use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\Storage\StorageAdapterInterface;
use Throwable;

/**
 * Adapter penyimpanan blob ciphertext berbasis Amazon S3.
 *
 * Mengimplementasikan {@see StorageAdapterInterface} dengan membungkus klien
 * S3 — biasanya `Aws\S3\S3Client` dari `aws/aws-sdk-php` (dependency OPSIONAL,
 * lihat `suggest`). Klien di-*duck-type*: cukup memiliki method
 * `putObject(array)`, `getObject(array)`, `headObject(array)`, dan
 * `deleteObject(array)`; hasilnya boleh `Aws\Result`, array, atau ArrayAccess.
 *
 * Key blob selalu divalidasi regex `[a-f0-9]{32}` (fail-closed anti path
 * traversal), konsisten dengan LocalStorageAdapter.
 *
 * Contoh wiring:
 *
 *     $client = new \Aws\S3\S3Client(['region' => 'ap-southeast-1', 'version' => 'latest']);
 *     $adapter = new S3StorageAdapter($client, ['bucket' => 'secure-files']);
 *     $storage = new SecureFileStorage(LocalKms::fromEnv(), $adapter);
 */
final class S3StorageAdapter implements StorageAdapterInterface
{
    private const KEY_PATTERN = '/^[a-f0-9]{32}$/';

    /** @var list<string> Method klien yang wajib tersedia (fail fast di konstruktor). */
    private const REQUIRED_METHODS = ['putObject', 'getObject', 'headObject', 'deleteObject'];

    private object $client;

    private string $bucket;

    /**
     * @param object               $s3Client Klien S3 (duck-typed).
     * @param array{bucket?:string} $opts    Opsi adapter; `bucket` wajib.
     */
    public function __construct(object $s3Client, array $opts = [])
    {
        foreach (self::REQUIRED_METHODS as $method) {
            if (!is_callable([$s3Client, $method])) {
                throw new SecurePayloadException(
                    "Klien AWS S3 harus memiliki method {$method}() "
                    . '(butuh salah satu dari: ' . implode(', ', self::REQUIRED_METHODS) . ')',
                    SecurePayloadException::BAD_REQUEST
                );
            }
        }
        $bucket = trim((string) ($opts['bucket'] ?? ''));
        if ($bucket === '') {
            throw new SecurePayloadException('S3StorageAdapter: nama bucket wajib diisi', SecurePayloadException::BAD_REQUEST);
        }
        $this->client = $s3Client;
        $this->bucket = $bucket;
    }

    public function put(string $key, string $contents): void
    {
        self::assertKey($key);
        try {
            call_user_func([$this->client, 'putObject'], [
                'Bucket' => $this->bucket,
                'Key'    => $key,
                'Body'   => $contents,
            ]);
        } catch (Throwable $e) {
            throw self::wrap($e, "gagal menyimpan blob '$key'");
        }
    }

    public function get(string $key): string
    {
        self::assertKey($key);
        try {
            $result = call_user_func([$this->client, 'getObject'], [
                'Bucket' => $this->bucket,
                'Key'    => $key,
            ]);
        } catch (Throwable $e) {
            throw self::wrap($e, "gagal membaca blob '$key'");
        }
        return self::bodyToString($result['Body'] ?? null, $key);
    }

    public function delete(string $key): void
    {
        self::assertKey($key);
        try {
            call_user_func([$this->client, 'deleteObject'], [
                'Bucket' => $this->bucket,
                'Key'    => $key,
            ]);
        } catch (Throwable $e) {
            throw self::wrap($e, "gagal menghapus blob '$key'");
        }
    }

    public function exists(string $key): bool
    {
        self::assertKey($key);
        try {
            call_user_func([$this->client, 'headObject'], [
                'Bucket' => $this->bucket,
                'Key'    => $key,
            ]);
            return true;
        } catch (Throwable $e) {
            // 404 / NoSuchKey → object tidak ada; error lain tetap dilempar.
            if (self::isNotFound($e)) {
                return false;
            }
            throw self::wrap($e, "gagal memeriksa keberadaan blob '$key'");
        }
    }

    /**
     * Validasi key fail-closed: harus hex lowercase tepat 32 karakter.
     */
    private static function assertKey(string $key): void
    {
        if (preg_match(self::KEY_PATTERN, $key) !== 1) {
            throw new SecurePayloadException("S3StorageAdapter: key tidak valid", SecurePayloadException::BAD_REQUEST);
        }
    }

    /**
     * Bungkus error SDK dengan konteks operasi Indonesia.
     */
    private static function wrap(Throwable $e, string $action): SecurePayloadException
    {
        return new SecurePayloadException(
            'S3StorageAdapter: ' . $action . ': ' . $e->getMessage(),
            SecurePayloadException::SERVER_ERROR,
            [],
            $e
        );
    }

    /**
     * Deteksi error "tidak ditemukan" dari SDK (404/NoSuchKey/NotFound).
     *
     * Ketat: substring pencocokan HANYA pada NAMA CLASS exception — bukan isi
     * pesan bebas — agar error lain yang kebetulan menyebut "not found" tidak
     * salah dipetakan sebagai 404.
     */
    private static function isNotFound(Throwable $e): bool
    {
        if (method_exists($e, 'getStatusCode') && (int) call_user_func([$e, 'getStatusCode']) === 404) {
            return true;
        }
        $code = (string) $e->getCode();
        if ($code === '404' || $code === 'NoSuchKey' || $code === 'NotFound') {
            return true;
        }
        $name = strtolower(get_class($e));
        return strpos($name, 'nosuchkey') !== false || strpos($name, 'notfound') !== false;
    }

    /**
     * Konversi Body hasil getObject ke string (dukung __toString/getContents/string).
     *
     * @param mixed $body
     */
    private static function bodyToString($body, string $key): string
    {
        if (is_string($body)) {
            return $body;
        }
        if (is_object($body)) {
            if (method_exists($body, 'getContents')) {
                $out = (string) call_user_func([$body, 'getContents']);
                if ($out !== '') {
                    return $out;
                }
            }
            if (method_exists($body, '__toString') || is_callable([$body, '__toString'])) {
                return (string) $body;
            }
        }
        throw new SecurePayloadException(
            "S3StorageAdapter: isi blob '$key' tidak dapat dibaca dari respons getObject",
            SecurePayloadException::SERVER_ERROR
        );
    }
}
