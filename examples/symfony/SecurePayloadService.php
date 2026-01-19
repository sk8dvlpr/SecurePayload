<?php
declare(strict_types=1);

namespace App\Service;

use SecurePayload\SecurePayload;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * SecurePayloadService (Symfony)
 * ------------------------------
 * Menggunakan Symfony HttpClient Component untuk mengirim request.
 */
class SecurePayloadService
{
    private SecurePayload $sp;
    private HttpClientInterface $client;

    public function __construct(HttpClientInterface $client)
    {
        $this->client = $client;

        // Init dengan kredensial dari parameters/env
        $this->sp = new SecurePayload([
            'mode' => 'both',
            'version' => '1',
            'clientId' => $_ENV['SP_CLIENT_ID'] ?? 'default',
            'keyId' => $_ENV['SP_KEY_ID'] ?? 'key1',
            'hmacSecretRaw' => hex2bin($_ENV['SP_HMAC_SECRET'] ?? ''),
            'aeadKeyB64' => $_ENV['SP_AEAD_KEY'] ?? '',
        ]);
    }

    public function sendSecureRequest(string $url, array $payload): array
    {
        $method = 'POST';

        // 1. Prepare
        [$headers, $bodyString] = $this->sp->buildHeadersAndBody($url, $method, $payload);

        // 2. Send
        $response = $this->client->request($method, $url, [
            'headers' => $headers,
            'body' => $bodyString
        ]);

        // 3. Return content (misal array)
        return $response->toArray();
    }
}
