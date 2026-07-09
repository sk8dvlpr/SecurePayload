<?php
declare(strict_types=1);

namespace SecurePayload\Ci4\Libraries;

use CodeIgniter\HTTP\CURLRequest;
use Config\Services;
use SecurePayload\Ci4\Config\SecurePayload as SecurePayloadConfig;
use SecurePayload\Ci4\SecurePayloadFactory;
use SecurePayload\SecurePayload;

final class SecurePayloadClient
{
    private SecurePayload $client;
    private CURLRequest $http;
    private string $baseUrl;

    public function __construct(?SecurePayloadConfig $config = null)
    {
        $cfg = $config ?? config('SecurePayload');
        $array = $cfg instanceof SecurePayloadConfig ? $cfg->toArray() : SecurePayloadFactory::defaultConfig();
        $this->client = SecurePayloadFactory::createClient($array);
        $this->baseUrl = (string) ($array['client']['base_url'] ?? '');
        $this->http = Services::curlrequest();
    }

    /**
     * @param array<string,mixed> $payload
     * @return array<string,mixed>
     */
    public function post(string $uri, array $payload): array
    {
        $fullUrl = rtrim($this->baseUrl, '/') . '/' . ltrim($uri, '/');
        [$headers, $body] = $this->client->buildHeadersAndBody($fullUrl, 'POST', $payload);

        $response = $this->http->post($fullUrl, [
            'headers' => $headers,
            'body' => $body,
        ]);

        return json_decode((string) $response->getBody(), true) ?? [];
    }
}
