<?php
declare(strict_types=1);

namespace App\Libraries;

use CodeIgniter\HTTP\CURLRequest;
use Config\Services;
use SecurePayload\SecurePayload;

/**
 * SecurePayloadClient (CodeIgniter 4)
 * -----------------------------------
 * Contoh library wrapper untuk mengirim request keluar (Outgoing Request)
 * yang diamankan dengan SecurePayload.
 */
class SecurePayloadClient
{
    private SecurePayload $sp;
    private CURLRequest $http;
    private string $targetBaseUrl;

    public function __construct()
    {
        // 1. Setup Kredensial (Biasanya dari .env)
        // Client ID dan Keys kita sendiri untuk identifikasi ke server tujuan
        $clientId = getenv('MY_CLIENT_ID') ?: 'client_001';
        $keyId = getenv('MY_KEY_ID') ?: 'key_v1';
        $hmacSecret = getenv('MY_HMAC_SECRET') ?: 'deadbeef...'; // HEX string
        $aeadKey = getenv('MY_AEAD_KEY_B64');

        // 2. Inisialisasi SecurePayload Client Mode
        $this->sp = new SecurePayload([
            'mode' => 'both',
            'version' => '1',
            'clientId' => $clientId,
            'keyId' => $keyId,
            'hmacSecretRaw' => hex2bin($hmacSecret),
            'aeadKeyB64' => $aeadKey,
        ]);

        // 3. Init HTTP Client (CI4 CURLRequest)
        $this->http = Services::curlrequest([
            'timeout' => 5,
        ]);

        $this->targetBaseUrl = 'https://api.tujuan.com';
    }

    /**
     * Mengirim POST request aman ke endpoint tujuan.
     */
    public function sendSecurePost(string $endpoint, array $data): \CodeIgniter\HTTP\ResponseInterface
    {
        $url = $this->targetBaseUrl . $endpoint;
        $method = 'POST';

        // 1. Generate Headers dan Body Terenkripsi/Tanda Tangan
        // SecurePayload akan menangani enkripsi body (jika mode AEAD)
        // dan pembuatan header X-Signature, X-Nonce, dll.
        [$headers, $finalBody] = $this->sp->buildHeadersAndBody($url, $method, $data);

        // 2. Kirim Request via HTTP Client Framework
        return $this->http->request($method, $url, [
            'headers' => $headers,
            'body' => $finalBody
        ]);
    }
}
