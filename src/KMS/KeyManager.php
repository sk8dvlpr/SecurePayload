<?php
declare(strict_types=1);

namespace SecurePayload\KMS;

use RuntimeException;

/**
 * KeyManager
 * ----------
 * Utility Helper untuk membantu generate, encrypt (wrap), dan menyiapkan SQL
 * untuk manajemen kunci (Key Management) SecurePayload.
 *
 * Penggunaan:
 * $km = new KeyManager($kmsInstance); // KMS opsional jika hanya butuh HMAC plaintext
 * $keys = $km->generateKeyPair('client_001', 'key_v1_2024');
 * echo $keys->toSqlInsert('secure_keys');
 */
final class KeyManager
{
    private ?Kms $kms;

    public function __construct(?Kms $kms = null)
    {
        $this->kms = $kms;
    }

    /**
     * Generate pasangan kunci baru (HMAC Secret + AEAD Key).
     * Jika KMS tersedia, AEAD Key akan otomatis di-wrap (enkripsi).
     *
     * @param string $clientId
     * @param string $keyId
     * @param string|null $kekId ID KEK (Key Encryption Key) yang ada di KMS. Wajib jika $kms ada.
     * 
     * @return GeneratedKeyResult Objek hasil yang berisi raw key dan SQL/Data siap simpan.
     */
    public function generateKeyPair(string $clientId, string $keyId, ?string $kekId = null): GeneratedKeyResult
    {
        // 1. Generate secrets
        // HMAC: 32 bytes hex string (64 chars) atau raw random bytes?
        // SecurePayload mendukung string raw apa saja, tapi praktik baik: 32 bytes high entropy.
        $hmacRaw = bin2hex(random_bytes(32));

        // AEAD: WAJIB 32 bytes raw
        $aeadRaw = random_bytes(32);
        $aeadB64 = base64_encode($aeadRaw);

        $wrappedB64 = null;

        // 2. Wrap AEAD Key jika KMS aktif
        if ($this->kms && $kekId) {
            $context = [
                'client_id' => $clientId,
                'key_id' => $keyId,
                'purpose' => 'securepayload-aead-key',
            ];
            $wrappedB64 = $this->kms->wrap($kekId, $aeadRaw, $context);
        } elseif ($this->kms && !$kekId) {
            throw new RuntimeException('kekId wajib diisi jika KeyManager menggunakan KMS');
        }

        return new GeneratedKeyResult(
            $clientId,
            $keyId,
            $hmacRaw,
            $aeadB64,
            $wrappedB64,
            $kekId
        );
    }
}

/**
 * Value Object untuk hasil generate kunci.
 * Bisa di-cast ke array atau generate SQL.
 */
final class GeneratedKeyResult
{
    public function __construct(
        public string $clientId,
        public string $keyId,
        public string $hmacSecret,
        public string $aeadKeyB64,
        public ?string $wrappedKeyB64,
        public ?string $kekId
    ) {
    }

    public function toArray(): array
    {
        return [
            'client_id' => $this->clientId,
            'key_id' => $this->keyId,
            'hmac_secret' => $this->hmacSecret,
            // Jika wrapped tersedia, aead_key_b64 sebaiknya NULL di database agar aman
            // Tapi kita return semua info d sini untuk config Client side.
            'aead_key_b64' => $this->aeadKeyB64,
            'wrapped_b64' => $this->wrappedKeyB64,
            'kek_id' => $this->kekId,
        ];
    }

    /**
     * Buat statement SQL INSERT untuk database.
     * Secara otomatis men-set NULL pada kolom AEAD plaintext jika wrapped key tersedia (Keamanan++).
     */
    public function toSqlInsert(string $tableName = 'secure_keys'): string
    {
        $hmacSql = $this->q($this->hmacSecret);
        $kekSql = $this->kekId ? $this->q($this->kekId) : 'NULL';

        if ($this->wrappedKeyB64) {
            // Secure Mode: Simpan Wrapped Key, AEAD Plaintext NULL
            $wrapSql = $this->q($this->wrappedKeyB64);
            return sprintf(
                "INSERT INTO `%s` (client_id, key_id, hmac_secret, aead_key_b64, wrapped_b64, kek_id) VALUES (%s, %s, %s, NULL, %s, %s);",
                $tableName,
                $this->q($this->clientId),
                $this->q($this->keyId),
                $hmacSql,
                $wrapSql,
                $kekSql
            );
        } else {
            // Plain Mode: Simpan AEAD Plaintext, Wrapped NULL
            $aeadSql = $this->q($this->aeadKeyB64);
            return sprintf(
                "INSERT INTO `%s` (client_id, key_id, hmac_secret, aead_key_b64, wrapped_b64, kek_id) VALUES (%s, %s, %s, %s, NULL, NULL);",
                $tableName,
                $this->q($this->clientId),
                $this->q($this->keyId),
                $hmacSql,
                $aeadSql
            );
        }
    }

    private function q(string $s): string
    {
        // Simple escape for generated SQL output
        return "'" . addslashes($s) . "'";
    }
}
