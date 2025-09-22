<?php
declare(strict_types=1);

namespace SecurePayload\KMS;

interface SecureKeyProvider
{
    /**
     * Ambil rahasia milik kombinasi (clientId, keyId).
     * Return:
     *  [
     *    'hmacSecret' => ?string,   // RAW STRING (bukan base64)
     *    'aeadKeyB64' => ?string,   // BASE64 32 byte
     *  ]
     * Jika tidak ditemukan / tidak aktif, kembalikan [].
     */
    public function load(string $clientId, string $keyId): array;
}
