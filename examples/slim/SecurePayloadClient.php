<?php
declare(strict_types=1);

namespace App\Services;

use SecurePayload\SecurePayload;
use GuzzleHttp\ClientInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * SecurePayloadClient (Slim 4)
 * ----------------------------
 * Class helper untuk membuat outgoing request aman.
 * Diasumsikan menggunakan Guzzle sebagai HTTP Client (standar PSR-18).
 */
class SecurePayloadClient
{
    private SecurePayload $sp;
    private ClientInterface $httpClient;

    public function __construct(ClientInterface $httpClient, array $config)
    {
        $this->httpClient = $httpClient;

        $this->sp = new SecurePayload([
            'mode' => 'both',
            'version' => '1',
            'clientId' => $config['client_id'],
            'keyId' => $config['key_id'],
            'hmacSecretRaw' => hex2bin($config['hmac_secret']),
            'aeadKeyB64' => $config['aead_key'],
        ]);
    }

    public function post(string $url, array $jsonPayload): ResponseInterface
    {
        $method = 'POST';

        // 1. Buat Header & Body
        // Library ini akan melakukan hashing dan encryption otomatis.
        [$headers, $finalBody] = $this->sp->buildHeadersAndBody($url, $method, $jsonPayload);

        // 2. Kirim Request (PSR-7 Request via Guzzle)
        return $this->httpClient->request($method, $url, [
            'headers' => $headers,
            'body' => $finalBody
        ]);
    }
}
