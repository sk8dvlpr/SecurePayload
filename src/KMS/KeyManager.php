<?php
declare(strict_types=1);

namespace SecurePayload\KMS;

use InvalidArgumentException;
use RuntimeException;

/**
 * KeyManager
 * ----------
 * Utility Helper untuk membantu generate, encrypt (wrap), rotasi, dan menyiapkan SQL
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

    /**
     * Rotasi kunci: generate keyId baru, tandai key lama sebagai retiring dengan grace window.
     *
     * @throws InvalidArgumentException Jika graceSeconds <= 0.
     * @throws RuntimeException         Jika sodium diperlukan tapi tidak tersedia.
     */
    public function rotateKey(
        string $clientId,
        string $currentKeyId,
        ?string $newKeyId = null,
        int $graceSeconds = 86400,
        ?string $kekId = null,
        bool $includeEd25519Client = false,
        bool $includeEd25519Server = false
    ): KeyRotationResult {
        if ($graceSeconds <= 0) {
            throw new InvalidArgumentException('graceSeconds harus lebih besar dari 0');
        }

        if ($newKeyId === null || $newKeyId === '') {
            $newKeyId = $currentKeyId . '_rot_' . date('YmdHis');
        }

        $newKey = $this->generateKeyPair($clientId, $newKeyId, $kekId);

        $ed25519PublicB64 = null;
        $ed25519SecretB64 = null;
        $ed25519ServerSecretB64 = null;
        $ed25519ServerPublicB64 = null;

        if ($includeEd25519Client) {
            $ed25519Client = $this->generateEd25519KeyPair();
            $ed25519PublicB64 = $ed25519Client['publicB64'];
            $ed25519SecretB64 = $ed25519Client['secretB64'];
        }

        if ($includeEd25519Server) {
            $ed25519Server = $this->generateEd25519ServerKeyPair();
            $ed25519ServerSecretB64 = $ed25519Server['secretB64'];
            $ed25519ServerPublicB64 = $ed25519Server['publicB64'];
        }

        $newKeyWithExtras = new GeneratedKeyResult(
            $newKey->clientId,
            $newKey->keyId,
            $newKey->hmacSecret,
            $newKey->aeadKeyB64,
            $newKey->wrappedKeyB64,
            $newKey->kekId,
            $ed25519PublicB64,
            $ed25519ServerSecretB64,
            $ed25519ServerPublicB64
        );

        return new KeyRotationResult(
            $clientId,
            $currentKeyId,
            $newKeyId,
            time() + $graceSeconds,
            $newKeyWithExtras,
            $ed25519SecretB64
        );
    }

    /**
     * Revoke kunci segera (tanpa grace period).
     *
     * @throws InvalidArgumentException Jika nama tabel tidak valid.
     */
    public function revokeKey(string $clientId, string $keyId, string $table = 'secure_keys'): string
    {
        $table = $this->qIdentifier($table);

        return sprintf(
            "UPDATE `%s` SET status = '%s', valid_until = NULL WHERE client_id = %s AND key_id = %s;",
            $table,
            KeyStatus::REVOKED,
            $this->qValue($clientId),
            $this->qValue($keyId)
        );
    }

    /**
     * SQL untuk menandai kunci retiring yang sudah lewat valid_until sebagai revoked (cron cleanup).
     *
     * @param int|null $now Unix timestamp acuan; default time().
     *
     * @throws InvalidArgumentException Jika nama tabel tidak valid.
     */
    public function purgeExpiredRetiringKeys(string $table = 'secure_keys', ?int $now = null): string
    {
        $table = $this->qIdentifier($table);
        $now = $now ?? time();

        return sprintf(
            "UPDATE `%s` SET status = '%s', valid_until = NULL WHERE status = '%s' AND valid_until IS NOT NULL AND valid_until < %d;",
            $table,
            KeyStatus::REVOKED,
            KeyStatus::RETIRING,
            $now
        );
    }

    /**
     * Generate pasangan kunci asimetris Ed25519 (untuk signAlg='ed25519').
     *
     * Mengembalikan public key (untuk server, disimpan di DB) dan secret key
     * (untuk client, JANGAN disimpan di server). Memerlukan ekstensi sodium.
     *
     * @return array{publicB64:string, secretB64:string} Pasangan kunci dalam base64.
     * @throws RuntimeException Jika ekstensi sodium tidak tersedia.
     */
    public function generateEd25519KeyPair(): array
    {
        if (!extension_loaded('sodium')) {
            throw new RuntimeException('Ekstensi sodium diperlukan untuk membangkitkan kunci Ed25519');
        }
        $pair = sodium_crypto_sign_keypair();
        return [
            'publicB64' => base64_encode(sodium_crypto_sign_publickey($pair)),
            'secretB64' => base64_encode(sodium_crypto_sign_secretkey($pair)),
        ];
    }

    /**
     * Generate pasangan kunci Ed25519 untuk server (signing response).
     *
     * @return array{publicB64:string, secretB64:string}
     * @throws RuntimeException Jika ekstensi sodium tidak tersedia.
     */
    public function generateEd25519ServerKeyPair(): array
    {
        return $this->generateEd25519KeyPair();
    }

    /**
     * @throws InvalidArgumentException Jika nama tabel tidak valid.
     */
    private function qIdentifier(string $id): string
    {
        if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $id)) {
            throw new InvalidArgumentException(
                "Nama tabel tidak valid: '$id'. Hanya huruf, angka, dan underscore yang diizinkan."
            );
        }
        return $id;
    }

    private function qValue(string $s): string
    {
        return "'" . addslashes($s) . "'";
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
        public ?string $kekId,
        public ?string $ed25519PublicB64 = null,
        public ?string $ed25519ServerSecretB64 = null,
        public ?string $ed25519ServerPublicB64 = null
    ) {
    }

    public function toArray(): array
    {
        $data = [
            'client_id' => $this->clientId,
            'key_id' => $this->keyId,
            'hmac_secret' => $this->hmacSecret,
            // Jika wrapped tersedia, aead_key_b64 sebaiknya NULL di database agar aman
            // Tapi kita return semua info d sini untuk config Client side.
            'aead_key_b64' => $this->aeadKeyB64,
            'wrapped_b64' => $this->wrappedKeyB64,
            'kek_id' => $this->kekId,
        ];

        if ($this->ed25519PublicB64 !== null) {
            $data['ed25519_public_b64'] = $this->ed25519PublicB64;
        }
        if ($this->ed25519ServerSecretB64 !== null) {
            $data['ed25519_server_secret_b64'] = $this->ed25519ServerSecretB64;
        }
        if ($this->ed25519ServerPublicB64 !== null) {
            $data['ed25519_server_public_b64'] = $this->ed25519ServerPublicB64;
        }

        return $data;
    }

    /**
     * Buat statement SQL INSERT untuk database.
     * Secara otomatis men-set NULL pada kolom AEAD plaintext jika wrapped key tersedia (Keamanan++).
     *
     * @param string $tableName        Nama tabel tujuan.
     * @param string $status           Status lifecycle (active/retiring/revoked).
     * @param bool   $includeLifecycle Sertakan kolom status + valid_until.
     */
    public function toSqlInsert(
        string $tableName = 'secure_keys',
        string $status = KeyStatus::ACTIVE,
        bool $includeLifecycle = false
    ): string {
        $tableName = $this->qIdentifier($tableName);

        $columns = ['client_id', 'key_id', 'hmac_secret', 'aead_key_b64', 'wrapped_b64', 'kek_id'];
        $values = [
            $this->q($this->clientId),
            $this->q($this->keyId),
            $this->q($this->hmacSecret),
        ];

        $kekSql = $this->kekId ? $this->q($this->kekId) : 'NULL';

        if ($this->wrappedKeyB64) {
            $wrapSql = $this->q($this->wrappedKeyB64);
            $values[] = 'NULL';
            $values[] = $wrapSql;
            $values[] = $kekSql;
        } else {
            $aeadSql = $this->q($this->aeadKeyB64);
            $values[] = $aeadSql;
            $values[] = 'NULL';
            $values[] = 'NULL';
        }

        if ($this->ed25519PublicB64 !== null && $this->ed25519PublicB64 !== '') {
            $columns[] = 'ed25519_public_b64';
            $values[] = $this->q($this->ed25519PublicB64);
        }
        if ($this->ed25519ServerSecretB64 !== null && $this->ed25519ServerSecretB64 !== '') {
            $columns[] = 'ed25519_server_secret_b64';
            $values[] = $this->q($this->ed25519ServerSecretB64);
        }
        if ($this->ed25519ServerPublicB64 !== null && $this->ed25519ServerPublicB64 !== '') {
            $columns[] = 'ed25519_server_public_b64';
            $values[] = $this->q($this->ed25519ServerPublicB64);
        }

        if ($includeLifecycle) {
            $columns[] = 'status';
            $columns[] = 'valid_until';
            $values[] = $this->q($status);
            $values[] = 'NULL';
        }

        return sprintf(
            'INSERT INTO `%s` (%s) VALUES (%s);',
            $tableName,
            implode(', ', $columns),
            implode(', ', $values)
        );
    }

    private function q(string $s): string
    {
        // Simple escape for generated SQL output
        return "'" . addslashes($s) . "'";
    }

    /**
     * Validasi identifier SQL (nama tabel) dengan whitelist.
     * Hanya mengizinkan huruf, angka, dan underscore untuk mencegah SQL injection,
     * karena identifier ini di-interpolasi langsung ke query (tidak bisa di-bind).
     *
     * @throws \InvalidArgumentException Jika nama tabel tidak valid.
     */
    private function qIdentifier(string $id): string
    {
        if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $id)) {
            throw new \InvalidArgumentException(
                "Nama tabel tidak valid: '$id'. Hanya huruf, angka, dan underscore yang diizinkan."
            );
        }
        return $id;
    }
}

/**
 * Value Object hasil rotasi kunci.
 */
final class KeyRotationResult
{
    public function __construct(
        public string $clientId,
        public string $oldKeyId,
        public string $newKeyId,
        public int $graceEndsAt,
        public GeneratedKeyResult $newKey,
        public ?string $ed25519SecretKeyB64 = null
    ) {
    }

    public function toSqlUpdateRetiring(string $tableName = 'secure_keys'): string
    {
        $tableName = $this->qIdentifier($tableName);

        return sprintf(
            "UPDATE `%s` SET status = '%s', valid_until = %d WHERE client_id = %s AND key_id = %s;",
            $tableName,
            KeyStatus::RETIRING,
            $this->graceEndsAt,
            $this->q($this->clientId),
            $this->q($this->oldKeyId)
        );
    }

    public function toSqlInsertNew(string $tableName = 'secure_keys'): string
    {
        return $this->newKey->toSqlInsert($tableName, KeyStatus::ACTIVE, true);
    }

    private function q(string $s): string
    {
        return "'" . addslashes($s) . "'";
    }

    /**
     * @throws InvalidArgumentException Jika nama tabel tidak valid.
     */
    private function qIdentifier(string $id): string
    {
        if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $id)) {
            throw new InvalidArgumentException(
                "Nama tabel tidak valid: '$id'. Hanya huruf, angka, dan underscore yang diizinkan."
            );
        }
        return $id;
    }
}
