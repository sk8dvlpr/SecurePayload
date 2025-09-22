<?php
declare(strict_types=1);

namespace SecurePayload\KMS;

use PDO;
use RuntimeException;

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

    private ?Kms $kms;

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

    /** @return array{hmacSecret:?string,aeadKeyB64:?string} */
    public function load(string $clientId, string $keyId): array
    {
        $sql = sprintf(
            "SELECT %s, %s, %s, %s FROM %s WHERE %s = :cid AND %s = :kid LIMIT 1",
            $this->q($this->colHmac),
            $this->q($this->colAeadB64),
            $this->q($this->colWrapped),
            $this->q($this->colKekId),
            $this->q($this->table),
            $this->q($this->colClient),
            $this->q($this->colKey),
        );
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':cid' => $clientId, ':kid' => $keyId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            return ['hmacSecret'=>null,'aeadKeyB64'=>null];
        }

        $hmacSecret = $row[$this->colHmac] ?? null;
        $aeadKeyB64 = $row[$this->colAeadB64] ?? null;
        $wrappedB64 = $row[$this->colWrapped] ?? null;
        $kekId      = $row[$this->colKekId] ?? null;

        if (($aeadKeyB64 === null || $aeadKeyB64 === '') && is_string($wrappedB64) && $wrappedB64 !== '' && is_string($kekId) && $kekId !== '') {
            if (!$this->kms) throw new RuntimeException('KMS is required to unwrap AEAD key');
            $aeadKeyRaw = $this->kms->unwrap((string)$kekId, (string)$wrappedB64, [
                'client_id' => $clientId,
                'key_id'    => $keyId,
                'purpose'   => 'securepayload-aead-key',
            ]);
            if (strlen($aeadKeyRaw) !== 32) throw new RuntimeException('Unwrapped AEAD key must be 32 bytes');
            $aeadKeyB64 = base64_encode($aeadKeyRaw);
        }

        return [
            'hmacSecret' => ($hmacSecret !== null && $hmacSecret !== '' ? (string)$hmacSecret : null),
            'aeadKeyB64' => ($aeadKeyB64 !== null && $aeadKeyB64 !== '' ? (string)$aeadKeyB64 : null),
        ];
    }

    private function q(string $id): string { return '`' . str_replace('`','``',$id) . '`'; }
}
