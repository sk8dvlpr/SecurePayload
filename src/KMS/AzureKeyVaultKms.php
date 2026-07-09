<?php
declare(strict_types=1);

namespace SecurePayload\KMS;

use RuntimeException;

/**
 * Adapter KMS berbasis Azure Key Vault Cryptography (Phase 15).
 *
 * Mengimplementasikan {@see Kms} dengan membungkus klien kriptografi Key Vault —
 * biasanya `Azure\Security\KeyVault\Keys\Cryptography\CryptographyClient` dari
 * `azure/keyvault-keys` (dependency OPSIONAL, lihat `suggest`). Klien cukup
 * memiliki method `encrypt(array): mixed` dan `decrypt(array): mixed`.
 *
 * Kontrak AAD dipetakan ke **additionalAuthenticatedData** Azure (map string→string
 * ter-ksort, sama semantik {@see AwsKms::context}). Gunakan kunci RSA-OAEP atau
 * symmetric key di vault yang mendukung encrypt/decrypt untuk payload 32-byte.
 *
 * Contoh wiring:
 *
 *     $crypto = new CryptographyClient('https://vault.vault.azure.net', $credential, 'my-key');
 *     $kms = new AzureKeyVaultKms($crypto);
 *
 * Adapter ini TIDAK mengubah format wire — hanya cara kunci AEAD di-*wrap/unwrap*.
 */
final class AzureKeyVaultKms implements Kms
{
    private object $client;
    private ?string $defaultKeyName;

    /**
     * @param object  $cryptoClient   Klien Azure Key Vault Cryptography.
     * @param ?string $defaultKeyName Nama kunci default bila kekId kosong.
     */
    public function __construct(object $cryptoClient, ?string $defaultKeyName = null)
    {
        if (!is_callable([$cryptoClient, 'encrypt']) || !is_callable([$cryptoClient, 'decrypt'])) {
            throw new RuntimeException('Klien Azure Key Vault harus memiliki method encrypt() dan decrypt()');
        }
        $this->client = $cryptoClient;
        $this->defaultKeyName = $defaultKeyName;
    }

    public function wrap(string $kekId, string $plaintext, array $aad): string
    {
        $keyName = $kekId !== '' ? $kekId : (string) $this->defaultKeyName;
        if ($keyName === '') {
            throw new RuntimeException('Azure Key Vault: nama kunci (kekId) wajib diisi untuk encrypt');
        }
        $args = [
            'algorithm' => 'RSA-OAEP',
            'value' => $plaintext,
            'additionalAuthenticatedData' => self::context($aad),
        ];
        if ($keyName !== '') {
            $args['keyName'] = $keyName;
        }
        $result = call_user_func([$this->client, 'encrypt'], $args);
        $blob = self::resultField($result, 'result') ?? self::resultField($result, 'ciphertext');
        if (!is_string($blob) || $blob === '') {
            throw new RuntimeException('Azure Key Vault: ciphertext kosong pada respons encrypt');
        }
        return base64_encode($blob);
    }

    public function unwrap(string $kekId, string $blobB64, array $aad): string
    {
        $ct = base64_decode($blobB64, true);
        if ($ct === false || $ct === '') {
            throw new RuntimeException('Azure Key Vault: wrapped blob rusak');
        }
        $args = [
            'algorithm' => 'RSA-OAEP',
            'value' => $ct,
            'additionalAuthenticatedData' => self::context($aad),
        ];
        $keyName = $kekId !== '' ? $kekId : (string) $this->defaultKeyName;
        if ($keyName !== '') {
            $args['keyName'] = $keyName;
        }
        $result = call_user_func([$this->client, 'decrypt'], $args);
        $pt = self::resultField($result, 'result') ?? self::resultField($result, 'plaintext');
        if (!is_string($pt)) {
            throw new RuntimeException('Azure Key Vault: plaintext kosong pada respons decrypt');
        }
        return $pt;
    }

    /**
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
        throw new RuntimeException("Azure Key Vault: tidak bisa membaca field '$field' dari hasil");
    }
}
