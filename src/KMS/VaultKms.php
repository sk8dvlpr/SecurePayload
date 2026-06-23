<?php
declare(strict_types=1);

namespace SecurePayload\KMS;

use RuntimeException;

/**
 * Adapter KMS berbasis HashiCorp Vault — Transit Secrets Engine (Phase 7).
 *
 * Mengimplementasikan {@see Kms} (`wrap()`/`unwrap()`) memakai endpoint Transit:
 *   - wrap   → POST {address}/v1/{mount}/encrypt/{kekId}
 *   - unwrap → POST {address}/v1/{mount}/decrypt/{kekId}
 *
 * Kontrak AAD (`['client_id','key_id','purpose']`) dipetakan ke parameter
 * **`context`** Transit (base64 dari AAD yang di-`ksort` + json), konsisten dengan
 * {@see LocalKms}. Karena memakai `context`, kunci Transit WAJIB dibuat dengan
 * `derived=true`, mis:
 *
 *     vault secrets enable transit
 *     vault write -f transit/keys/<kekId> derived=true
 *
 * Transport HTTP dapat di-inject (untuk testing / klien kustom); default memakai
 * cURL. Tidak menambah dependency wajib — hanya `ext-curl` saat transport default.
 *
 * Catatan: adapter ini TIDAK mengubah format wire SecurePayload — hanya cara
 * kunci AEAD di-*wrap/unwrap* di sisi server.
 */
final class VaultKms implements Kms
{
    private string $address;
    private string $token;
    private string $mount;

    /** @var callable(string,string,array<int,string>,string):array{status:int,body:string} */
    private $transport;

    /**
     * @param string $address Base URL Vault (mis. https://vault.example.com:8200).
     * @param string $token   Vault token (X-Vault-Token).
     * @param string $mount   Path mount Transit (default 'transit').
     * @param callable|null $transport fn(string $method, string $url, array $headers, string $body): array{status:int,body:string}
     */
    public function __construct(string $address, string $token, string $mount = 'transit', ?callable $transport = null)
    {
        $this->address = rtrim($address, '/');
        $this->token = $token;
        $this->mount = trim($mount, '/');
        $this->transport = $transport ?? [self::class, 'curlTransport'];
    }

    public function wrap(string $kekId, string $plaintext, array $aad): string
    {
        $payload = ['plaintext' => base64_encode($plaintext)];
        $ctx = self::contextB64($aad);
        if ($ctx !== '') {
            $payload['context'] = $ctx;
        }
        $resp = $this->call('/v1/' . $this->mount . '/encrypt/' . rawurlencode($kekId), $payload);
        $ct = $resp['data']['ciphertext'] ?? null;
        if (!is_string($ct) || $ct === '') {
            throw new RuntimeException('Vault: ciphertext kosong pada respons encrypt');
        }
        // Simpan blob sebagai base64 dari string "vault:vN:..." agar seragam dengan Kms lain.
        return base64_encode($ct);
    }

    public function unwrap(string $kekId, string $blobB64, array $aad): string
    {
        $ct = base64_decode($blobB64, true);
        if ($ct === false || $ct === '') {
            throw new RuntimeException('Vault: wrapped blob rusak');
        }
        $payload = ['ciphertext' => $ct];
        $ctx = self::contextB64($aad);
        if ($ctx !== '') {
            $payload['context'] = $ctx;
        }
        $resp = $this->call('/v1/' . $this->mount . '/decrypt/' . rawurlencode($kekId), $payload);
        $ptB64 = $resp['data']['plaintext'] ?? null;
        if (!is_string($ptB64)) {
            throw new RuntimeException('Vault: plaintext kosong pada respons decrypt');
        }
        $pt = base64_decode($ptB64, true);
        if ($pt === false) {
            throw new RuntimeException('Vault: plaintext bukan base64 valid');
        }
        return $pt;
    }

    /**
     * Kirim request JSON ke Vault dan kembalikan body terdekode.
     *
     * @param array<string,mixed> $payload
     * @return array<string,mixed>
     */
    private function call(string $path, array $payload): array
    {
        $body = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if ($body === false) {
            throw new RuntimeException('Vault: gagal encode payload JSON');
        }
        $headers = [
            'X-Vault-Token: ' . $this->token,
            'Content-Type: application/json',
        ];
        $res = call_user_func($this->transport, 'POST', $this->address . $path, $headers, $body);
        $status = is_array($res) ? (int) ($res['status'] ?? 0) : 0;
        $respBody = is_array($res) ? (string) ($res['body'] ?? '') : '';
        if ($status < 200 || $status >= 300) {
            throw new RuntimeException("Vault HTTP $status: " . $respBody);
        }
        $json = json_decode($respBody, true);
        if (!is_array($json)) {
            throw new RuntimeException('Vault: respons bukan JSON yang valid');
        }
        return $json;
    }

    /**
     * Bangun parameter `context` Transit dari AAD (base64 dari ksort+json).
     *
     * @param array<string,mixed> $aad
     */
    private static function contextB64(array $aad): string
    {
        if ($aad === []) {
            return '';
        }
        ksort($aad);
        $j = json_encode($aad, JSON_UNESCAPED_SLASHES);
        return base64_encode($j === false ? '' : $j);
    }

    /**
     * Transport default berbasis cURL.
     *
     * @param array<int,string> $headers
     * @return array{status:int,body:string}
     */
    private static function curlTransport(string $method, string $url, array $headers, string $body): array
    {
        if (!extension_loaded('curl')) {
            throw new RuntimeException('ext-curl diperlukan untuk transport default VaultKms (atau inject transport sendiri)');
        }
        $ch = curl_init($url);
        if ($ch === false) {
            throw new RuntimeException('Vault: gagal inisialisasi cURL');
        }
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15);

        $resp = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = $resp === false ? curl_error($ch) : null;
        curl_close($ch);
        if ($resp === false) {
            throw new RuntimeException('Vault transport error: ' . (string) $err);
        }
        return ['status' => $status, 'body' => (string) $resp];
    }
}
