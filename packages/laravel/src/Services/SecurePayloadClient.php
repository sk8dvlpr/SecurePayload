<?php
declare(strict_types=1);

namespace SecurePayload\Laravel\Services;

use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use SecurePayload\SecurePayload;

final class SecurePayloadClient
{
    public function __construct(
        private readonly SecurePayload $client,
        private readonly string $baseUrl
    ) {
    }

    /**
     * @param array<string,mixed> $payload
     */
    public function post(string $uri, array $payload): Response
    {
        $fullUrl = rtrim($this->baseUrl, '/') . '/' . ltrim($uri, '/');
        [$headers, $body] = $this->client->buildHeadersAndBody($fullUrl, 'POST', $payload);

        return Http::withHeaders($headers)
            ->withBody($body, 'application/json')
            ->post($fullUrl);
    }
}
