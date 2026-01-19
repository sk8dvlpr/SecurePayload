<?php
declare(strict_types=1);

namespace App\Services;

use SecurePayload\SecurePayload;
use GuzzleHttp\Client;

/**
 * SecurePayloadService (Lumen)
 * ----------------------------
 * Service layer untuk komunikasi antar microservice dengan Lumen (Guzzle Wrapper).
 */
class SecurePayloadService
{
    private SecurePayload $sp;
    private Client $http;

    public function __construct()
    {
        // 1. Setup Creds
        $this->sp = new SecurePayload([
            'mode' => 'both',
            'version' => '1',
            'clientId' => env('SP_CLIENT_ID'),
            'keyId' => env('SP_KEY_ID'),
            'hmacSecretRaw' => hex2bin(env('SP_HMAC_SECRET')),
            'aeadKeyB64' => env('SP_AEAD_KEY'),
        ]);

        // 2. Setup Guzzle Client
        $this->http = new Client([
            'base_uri' => env('SP_TARGET_URL', 'https://api.internal.service'),
            'timeout' => 5.0,
        ]);
    }

    public function dispatch(string $endpoint, array $data)
    {
        $url = $endpoint; // Guzzle base_uri akan menggabungkan ini
        // PERHATIAN: buildHeadersAndBody butuh Full URL untuk canonical path yang akurat path-nya
        // Jadi kita construct full URL manual untuk helper library
        $fullUrl = $this->http->getConfig('base_uri') . ltrim($endpoint, '/');

        $method = 'POST';

        // 1. Bungkus Payload
        [$headers, $body] = $this->sp->buildHeadersAndBody($fullUrl, $method, $data);

        // 2. Kirim
        return $this->http->request($method, $endpoint, [
            'headers' => $headers,
            'body' => $body
        ]);
    }
}
