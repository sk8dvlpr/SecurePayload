<?php
declare(strict_types=1);

namespace SecurePayload\Storage;

use SecurePayload\Exceptions\SecurePayloadException;

/**
 * Value object manifest file terenkripsi — bagian modul Storage inti.
 *
 * Manifest berisi SEMUA metadata yang dibutuhkan untuk membuka kembali
 * blob ciphertext, termasuk wrapped DEK dan konteks AAD binding.
 * Manifest inilah yang dipersist aplikasi pemakai di DB-nya; blob di
 * adapter murni ciphertext self-contained tanpa metadata.
 *
 * Objek immutable: hanya bisa dibangun via fromArray(), tidak ada setter.
 */
final class FileManifest
{
    private string $v;
    private string $alg;
    private string $fileId;
    private string $kekId;
    private string $wrappedDekB64;
    /** @var array<string,string> */
    private array $aadContext;
    private int $size;
    private string $cipherDigest;
    private int $chunkSize;
    private int $createdAt;
    /** @var array<string,string> */
    private array $metadata;

    /**
     * Konstruktor sengaja private — satu-satunya jalur pembuatan adalah
     * fromArray() agar validasi tidak bisa dilewati.
     *
     * @param array<string,string> $aadContext
     * @param array<string,string> $metadata
     */
    private function __construct(
        string $v,
        string $alg,
        string $fileId,
        string $kekId,
        string $wrappedDekB64,
        array $aadContext,
        int $size,
        string $cipherDigest,
        int $chunkSize,
        int $createdAt,
        array $metadata
    ) {
        $this->v = $v;
        $this->alg = $alg;
        $this->fileId = $fileId;
        $this->kekId = $kekId;
        $this->wrappedDekB64 = $wrappedDekB64;
        $this->aadContext = $aadContext;
        $this->size = $size;
        $this->cipherDigest = $cipherDigest;
        $this->chunkSize = $chunkSize;
        $this->createdAt = $createdAt;
        $this->metadata = $metadata;
    }

    /**
     * Bangun manifest dari array hasil toArray()/DB aplikasi.
     * Fail-closed: field wajib yang hilang atau bertipe salah ditolak.
     *
     * @param array<string,mixed> $data
     *
     * @throws SecurePayloadException BAD_REQUEST bila struktur manifest tidak valid.
     */
    public static function fromArray(array $data): self
    {
        $v = self::requireString($data, 'v');
        $alg = self::requireString($data, 'alg');
        $fileId = self::requireString($data, 'file_id');
        if (preg_match('/^[a-f0-9]{32}$/', $fileId) !== 1) {
            throw new SecurePayloadException("Field manifest 'file_id' harus 32 karakter hex lowercase", SecurePayloadException::BAD_REQUEST);
        }
        $kekId = self::requireString($data, 'kek_id');
        $wrappedDekB64 = self::requireString($data, 'wrapped_dek_b64');
        if (base64_decode($wrappedDekB64, true) === false) {
            throw new SecurePayloadException("Field manifest 'wrapped_dek_b64' bukan base64 yang valid", SecurePayloadException::BAD_REQUEST);
        }
        $aadContext = self::requireStringMap($data, 'aad_context');
        $size = self::requireInt($data, 'size');
        if ($size < 0) {
            throw new SecurePayloadException("Field manifest 'size' tidak boleh negatif", SecurePayloadException::BAD_REQUEST);
        }
        $cipherDigest = self::requireString($data, 'cipher_digest');
        if (!str_starts_with($cipherDigest, 'sha256=')) {
            throw new SecurePayloadException("Field manifest 'cipher_digest' wajib berformat 'sha256=<base64>'", SecurePayloadException::BAD_REQUEST);
        }
        $chunkSize = self::requireInt($data, 'chunk_size');
        if ($chunkSize <= 0) {
            throw new SecurePayloadException("Field manifest 'chunk_size' harus bilangan bulat positif", SecurePayloadException::BAD_REQUEST);
        }
        $createdAt = self::requireInt($data, 'created_at');
        if ($createdAt <= 0) {
            throw new SecurePayloadException("Field manifest 'created_at' harus unix timestamp positif", SecurePayloadException::BAD_REQUEST);
        }
        $metadata = self::requireStringMap($data, 'metadata');

        return new self($v, $alg, $fileId, $kekId, $wrappedDekB64, $aadContext, $size, $cipherDigest, $chunkSize, $createdAt, $metadata);
    }

    /**
     * Serialisasi ke array polos — aman untuk di-JSON-kan/dipersist ke DB.
     *
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        return [
            'v' => $this->v,
            'alg' => $this->alg,
            'file_id' => $this->fileId,
            'kek_id' => $this->kekId,
            'wrapped_dek_b64' => $this->wrappedDekB64,
            'aad_context' => $this->aadContext,
            'size' => $this->size,
            'cipher_digest' => $this->cipherDigest,
            'chunk_size' => $this->chunkSize,
            'created_at' => $this->createdAt,
            'metadata' => $this->metadata,
        ];
    }

    public function v(): string
    {
        return $this->v;
    }

    public function alg(): string
    {
        return $this->alg;
    }

    public function fileId(): string
    {
        return $this->fileId;
    }

    public function kekId(): string
    {
        return $this->kekId;
    }

    public function wrappedDekB64(): string
    {
        return $this->wrappedDekB64;
    }

    /** @return array<string,string> */
    public function aadContext(): array
    {
        return $this->aadContext;
    }

    public function size(): int
    {
        return $this->size;
    }

    public function cipherDigest(): string
    {
        return $this->cipherDigest;
    }

    public function chunkSize(): int
    {
        return $this->chunkSize;
    }

    public function createdAt(): int
    {
        return $this->createdAt;
    }

    /** @return array<string,string> */
    public function metadata(): array
    {
        return $this->metadata;
    }

    /**
     * Ambil field wajib bertipe string non-kosong, atau tolak.
     *
     * @param array<string,mixed> $data
     */
    private static function requireString(array $data, string $key): string
    {
        if (!isset($data[$key]) || !is_string($data[$key]) || $data[$key] === '') {
            throw new SecurePayloadException("Field manifest '$key' wajib ada dan bertipe string non-kosong", SecurePayloadException::BAD_REQUEST);
        }
        return $data[$key];
    }

    /**
     * Ambil field wajib bertipe int (bukan numeric-string), atau tolak.
     *
     * @param array<string,mixed> $data
     */
    private static function requireInt(array $data, string $key): int
    {
        if (!isset($data[$key]) || !is_int($data[$key])) {
            throw new SecurePayloadException("Field manifest '$key' wajib ada dan bertipe integer", SecurePayloadException::BAD_REQUEST);
        }
        return $data[$key];
    }

    /**
     * Ambil field wajib bertipe map string=>string, atau tolak.
     *
     * @param array<string,mixed> $data
     *
     * @return array<string,string>
     */
    private static function requireStringMap(array $data, string $key): array
    {
        if (!isset($data[$key]) || !is_array($data[$key])) {
            throw new SecurePayloadException("Field manifest '$key' wajib ada dan bertipe array", SecurePayloadException::BAD_REQUEST);
        }
        foreach ($data[$key] as $k => $val) {
            if (!is_string($k) || !is_string($val)) {
                throw new SecurePayloadException("Field manifest '$key' wajib berisi pasangan key/value string", SecurePayloadException::BAD_REQUEST);
            }
        }
        /** @var array<string,string> */
        return $data[$key];
    }
}
