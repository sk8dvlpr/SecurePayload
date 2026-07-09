<?php
declare(strict_types=1);

namespace SecurePayload\KMS;

use RuntimeException;

/**
 * Adapter KMS berbasis Google Cloud KMS (Phase 15).
 *
 * Mengimplementasikan {@see Kms} dengan membungkus klien Cloud KMS — biasanya
 * `Google\Cloud\Kms\V1\Client\KeyManagementServiceClient` dari `google/cloud-kms`
 * (dependency OPSIONAL, lihat `suggest`). Klien cukup memiliki method
 * `encrypt(array): mixed` dan `decrypt(array): mixed`; hasilnya boleh objek
 * dengan `get()`, array, atau ArrayAccess.
 *
 * Kontrak AAD (`['client_id','key_id','purpose']`) dipetakan ke
 * **additionalAuthenticatedData** GCP KMS (JSON ter-ksort). unwrap dengan AAD
 * berbeda akan gagal di sisi GCP, konsisten dengan {@see AwsKms}.
 *
 * Contoh wiring:
 *
 *     $client = new KeyManagementServiceClient();
 *     $kms = new GcpKms($client);
 *     $kms->wrap('projects/p/locations/l/keyRings/r/cryptoKeys/k', $pt, $aad);
 *
 * Adapter ini TIDAK mengubah format wire — hanya cara kunci AEAD di-*wrap/unwrap*.
 */
final class GcpKms implements Kms
{
    private object $client;
    private ?string $defaultKekId;

    /**
     * @param object  $kmsClient    Klien GCP KMS (punya encrypt()/decrypt()).
     * @param ?string $defaultKekId Nama resource crypto key default bila kekId kosong.
     */
    public function __construct(object $kmsClient, ?string $defaultKekId = null)
    {
        if (!is_callable([$kmsClient, 'encrypt']) || !is_callable([$kmsClient, 'decrypt'])) {
            throw new RuntimeException('Klien GCP KMS harus memiliki method encrypt() dan decrypt()');
        }
        $this->client = $kmsClient;
        $this->defaultKekId = $defaultKekId;
    }

    public function wrap(string $kekId, string $plaintext, array $aad): string
    {
        $name = $kekId !== '' ? $kekId : (string) $this->defaultKekId;
        if ($name === '') {
            throw new RuntimeException('GCP KMS: nama crypto key (kekId) wajib diisi untuk encrypt');
        }
        $result = call_user_func([$this->client, 'encrypt'], [
            'name' => $name,
            'plaintext' => $plaintext,
            'additionalAuthenticatedData' => self::aadBytes($aad),
        ]);
        $blob = self::resultField($result, 'ciphertext');
        if (!is_string($blob) || $blob === '') {
            throw new RuntimeException('GCP KMS: ciphertext kosong pada respons encrypt');
        }
        return base64_encode($blob);
    }

    public function unwrap(string $kekId, string $blobB64, array $aad): string
    {
        $ct = base64_decode($blobB64, true);
        if ($ct === false || $ct === '') {
            throw new RuntimeException('GCP KMS: wrapped blob rusak');
        }
        $args = [
            'ciphertext' => $ct,
            'additionalAuthenticatedData' => self::aadBytes($aad),
        ];
        $name = $kekId !== '' ? $kekId : (string) $this->defaultKekId;
        if ($name !== '') {
            $args['name'] = $name;
        }
        $result = call_user_func([$this->client, 'decrypt'], $args);
        $pt = self::resultField($result, 'plaintext');
        if (!is_string($pt)) {
            throw new RuntimeException('GCP KMS: plaintext kosong pada respons decrypt');
        }
        return $pt;
    }

    /**
     * Serialisasi AAD deterministik untuk additionalAuthenticatedData GCP KMS.
     *
     * @param array<string,mixed> $aad
     */
    private static function aadBytes(array $aad): string
    {
        ksort($aad);
        $out = [];
        foreach ($aad as $k => $v) {
            $out[(string) $k] = is_scalar($v) ? (string) $v : (string) json_encode($v);
        }
        return (string) json_encode($out, JSON_UNESCAPED_SLASHES);
    }

    /**
     * Ambil field dari hasil panggilan KMS.
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
        throw new RuntimeException("GCP KMS: tidak bisa membaca field '$field' dari hasil");
    }
}
