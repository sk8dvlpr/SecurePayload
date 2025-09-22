<?php
declare(strict_types=1);

namespace SecurePayload\KMS;

use PDO;
use RuntimeException;

/**
 * DbKeyProvider
 * -------------
 * Penyedia kunci berbasis database (PDO). Cocok untuk multi-client & rotation key.
 *
 * Skema default (bisa diubah via opsi):
 *  - Tabel: secure_keys
 *  - Kolom:
 *      client_id      VARCHAR
 *      key_id         VARCHAR
 *      hmac_secret    VARBINARY/TEXT   (RAW STRING, BUKAN base64)
 *      aead_key_b64   TEXT             (BASE64 dari 32-byte key)  -- jika tidak pakai KMS
 *      wrapped_b64    TEXT             (opsional, jika pakai KMS: base64(nonce||ciphertext))
 *      kek_id         VARCHAR          (opsional, id KEK untuk unwrap)
 *
 * Pilih salah satu sumber AEAD:
 *  - aead_key_b64 langsung, ATAU
 *  - wrapped_b64 + kek_id (butuh implementasi KMS untuk unwrap)
 */
final class DbKeyProvider implements SecureKeyProvider
{
    private PDO $pdo;
    private string $table;
    private string $colClient;
    private string $colKey;
    private string $colHmac;
    private string $colAeadB64;
    private string $colWrapped;
    private string $colKekId;

    /** @var Kms|null */
    private ?Kms $kms;

    /**
     * @param array{
     *   table?: string,
     *   colClient?: string,
     *   colKey?: string,
     *   colHmac?: string,
     *   colAeadB64?: string,
     *   colWrapped?: string,
     *   colKekId?: string
     * } $opts
     */
    public function __construct(PDO $pdo, array $opts = [], ?Kms $kms = null)
    {
        $this->pdo = $pdo;
        $this->table = $opts['table'] ?? 'secure_keys';
        $this->colClient = $opts['colClient'] ?? 'client_id';
        $this->colKey    = $opts['colKey']    ?? 'key_id';
        $this->colHmac   = $opts['colHmac']   ?? 'hmac_secret';
        $this->colAeadB64= $opts['colAeadB64']?? 'aead_key_b64';
        $this->colWrapped= $opts['colWrapped']?? 'wrapped_b64';
        $this->colKekId  = $opts['colKekId']  ?? 'kek_id';
        $this->kms = $kms;
    }

    public function load(string $clientId, string $keyId): array
    {
        $sql = sprintf(
            "SELECT %s, %s, %s, %s FROM %s WHERE %s = :cid AND %s = :kid LIMIT 1",
            $this->quoteIdent($this->colHmac),
            $this->quoteIdent($this->colAeadB64),
            $this->quoteIdent($this->colWrapped),
            $this->quoteIdent($this->colKekId),
            $this->quoteIdent($this->table),
            $this->quoteIdent($this->colClient),
            $this->quoteIdent($this->colKey),
        );
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':cid' => $clientId, ':kid' => $keyId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) return [];

        $hmacSecret = $row[$this->colHmac] ?? null;
        $aeadKeyB64 = $row[$this->colAeadB64] ?? null;
        $wrappedB64 = $row[$this->colWrapped] ?? null;
        $kekId      = $row[$this->colKekId] ?? null;

        // unwrap jika perlu
        if ((!$aeadKeyB64 || strlen((string)$aeadKeyB64) === 0) && $wrappedB64 && $kekId) {
            if (!$this->kms) throw new RuntimeException('KMS is required to unwrap AEAD key');
            $aeadKeyRaw = $this->kms->unwrap((string)$kekId, (string)$wrappedB64, [
                'client_id' => $clientId,
                'key_id'    => $keyId,
                'purpose'   => 'securepayload-aead-key',
            ]);
            if (strlen($aeadKeyRaw) !== 32) {
                throw new RuntimeException('Unwrapped AEAD key must be 32 bytes');
            }
            $aeadKeyB64 = base64_encode($aeadKeyRaw);
        }

        return [
            'hmacSecret' => $hmacSecret !== null && $hmacSecret !== '' ? (string)$hmacSecret : null,
            'aeadKeyB64' => $aeadKeyB64 !== null && $aeadKeyB64 !== '' ? (string)$aeadKeyB64 : null,
        ];
    }

    private function quoteIdent(string $id): string
    {
        // sederhana: gunakan backtick (MySQL/MariaDB). Untuk DB lain, sesuaikan jika perlu.
        return '`' . str_replace('`','``',$id) . '`';
    }
}
