<?php
declare(strict_types=1);

namespace SecurePayload\KMS;

use RuntimeException;

/**
 * Adapter KMS berbasis AWS KMS (Phase 7).
 *
 * Mengimplementasikan {@see Kms} dengan membungkus sebuah klien AWS KMS — biasanya
 * `Aws\Kms\KmsClient` dari `aws/aws-sdk-php` (dependency OPSIONAL, lihat `suggest`).
 * Klien cukup memiliki method `encrypt(array): mixed` dan `decrypt(array): mixed`
 * yang kompatibel dengan SDK; hasilnya boleh `Aws\Result` (punya `get()`), array,
 * atau `ArrayAccess`.
 *
 * Kontrak AAD (`['client_id','key_id','purpose']`) dipetakan ke **EncryptionContext**
 * AWS KMS — yang memang berfungsi sebagai AAD. unwrap dengan context berbeda akan
 * gagal di sisi AWS (binding terjaga), konsisten dengan {@see LocalKms}.
 *
 * Contoh wiring:
 *
 *     $client = new \Aws\Kms\KmsClient(['region' => 'ap-southeast-1', 'version' => 'latest']);
 *     $kms = new AwsKms($client); // kekId = ARN/alias key dilewatkan per-wrap()
 *
 * Adapter ini TIDAK mengubah format wire — hanya cara kunci AEAD di-*wrap/unwrap*.
 */
final class AwsKms implements Kms
{
    private object $client;
    private ?string $defaultKekId;

    /**
     * @param object  $kmsClient    Klien AWS KMS (punya encrypt()/decrypt()).
     * @param ?string $defaultKekId KeyId/alias/ARN default bila tidak dilewatkan ke wrap().
     */
    public function __construct(object $kmsClient, ?string $defaultKekId = null)
    {
        if (!is_callable([$kmsClient, 'encrypt']) || !is_callable([$kmsClient, 'decrypt'])) {
            throw new RuntimeException('Klien AWS KMS harus memiliki method encrypt() dan decrypt()');
        }
        $this->client = $kmsClient;
        $this->defaultKekId = $defaultKekId;
    }

    public function wrap(string $kekId, string $plaintext, array $aad): string
    {
        $keyId = $kekId !== '' ? $kekId : (string) $this->defaultKekId;
        if ($keyId === '') {
            throw new RuntimeException('AWS KMS: KeyId (kekId) wajib diisi untuk encrypt');
        }
        $result = call_user_func([$this->client, 'encrypt'], [
            'KeyId' => $keyId,
            'Plaintext' => $plaintext,
            'EncryptionContext' => self::context($aad),
        ]);
        $blob = self::resultField($result, 'CiphertextBlob');
        if (!is_string($blob) || $blob === '') {
            throw new RuntimeException('AWS KMS: CiphertextBlob kosong pada respons encrypt');
        }
        return base64_encode($blob);
    }

    public function unwrap(string $kekId, string $blobB64, array $aad): string
    {
        $ct = base64_decode($blobB64, true);
        if ($ct === false || $ct === '') {
            throw new RuntimeException('AWS KMS: wrapped blob rusak');
        }
        $args = [
            'CiphertextBlob' => $ct,
            'EncryptionContext' => self::context($aad),
        ];
        // KeyId opsional untuk decrypt (AWS dapat menyimpulkan dari blob), sertakan bila ada.
        if ($kekId !== '') {
            $args['KeyId'] = $kekId;
        }
        $result = call_user_func([$this->client, 'decrypt'], $args);
        $pt = self::resultField($result, 'Plaintext');
        if (!is_string($pt)) {
            throw new RuntimeException('AWS KMS: Plaintext kosong pada respons decrypt');
        }
        return $pt;
    }

    /**
     * Petakan AAD ke EncryptionContext (map string→string, di-ksort untuk determinisme).
     *
     * @param array<string,mixed> $aad
     * @return array<string,string>
     */
    private static function context(array $aad): array
    {
        ksort($aad);
        $out = [];
        foreach ($aad as $k => $v) {
            $out[(string) $k] = is_scalar($v) ? (string) $v : (string) json_encode($v);
        }
        return $out;
    }

    /**
     * Ambil sebuah field dari hasil panggilan KMS (Aws\Result, array, atau ArrayAccess).
     *
     * @param mixed $result
     * @return mixed
     */
    private static function resultField($result, string $field)
    {
        if (is_object($result) && is_callable([$result, 'get'])) {
            return call_user_func([$result, 'get'], $field);
        }
        if (is_array($result) || $result instanceof \ArrayAccess) {
            return $result[$field] ?? null;
        }
        throw new RuntimeException("AWS KMS: tidak bisa membaca field '$field' dari hasil");
    }
}
