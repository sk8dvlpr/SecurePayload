<?php
declare(strict_types=1);

namespace SecurePayload\Symfony\Service;

use SecurePayload\SecurePayload;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class SecurePayloadClient
{
    public function __construct(
        private readonly SecurePayload $client,
        private readonly HttpClientInterface $httpClient,
        private readonly string $baseUrl
    ) {
    }

    /**
     * @param array<string,mixed> $payload
     * @return array<string,mixed>
     */
    public function post(string $uri, array $payload): array
    {
        $fullUrl = rtrim($this->baseUrl, '/') . '/' . ltrim($uri, '/');
        [$headers, $body] = $this->client->buildHeadersAndBody($fullUrl, 'POST', $payload);

        $response = $this->httpClient->request('POST', $fullUrl, [
            'headers' => $headers,
            'body' => $body,
        ]);

        return $response->toArray();
    }
}
