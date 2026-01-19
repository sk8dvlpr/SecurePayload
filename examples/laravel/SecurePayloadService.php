<?php
declare(strict_types=1);

namespace App\Services;

use Illuminate\Support\Facades\Http;
use SecurePayload\SecurePayload;

/**
 * SecurePayloadService (Laravel)
 * ------------------------------
 * Service untuk mengirim request aman ke server lain menggunakan HTTP Facade.
 */
class SecurePayloadService
{
    private SecurePayload $sp;
    private string $baseUrl;

    public function __construct()
    {
        // 1. Load Config/Env
        $this->sp = new SecurePayload([
            'mode' => 'both',
            'version' => '1',
            'clientId' => config('services.securepayload.client_id'),
            'keyId' => config('services.securepayload.key_id'),
            'hmacSecretRaw' => hex2bin(config('services.securepayload.hmac_secret')),
            'aeadKeyB64' => config('services.securepayload.aead_key'),
        ]);

        $this->baseUrl = config('services.securepayload.base_url', 'https://api.partner.com');
    }

    /**
     * Kirim data aman.
     * 
     * @param string $uri Contoh: '/v1/transaction'
     * @param array $payload Data JSON/Array
     * @return \Illuminate\Http\Client\Response
     */
    public function postSecure(string $uri, array $payload)
    {
        $fullUrl = $this->baseUrl . $uri;
        $method = 'POST';

        // 1. Build Secure Headers & Body
        // Library otomatis mengenkripsi payload jika mode = AEAD/BOTH
        [$headers, $secureBody] = $this->sp->buildHeadersAndBody($fullUrl, $method, $payload);

        // 2. Kirim via Laravel Http Client
        return Http::withHeaders($headers)
            ->withBody($secureBody, 'application/json') // Content-type bisa disesuaikan
            ->post($fullUrl);
    }
}
