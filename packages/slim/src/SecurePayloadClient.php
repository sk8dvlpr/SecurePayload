<?php
declare(strict_types=1);

namespace SecurePayload\Slim;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use SecurePayload\SecurePayload;

final class SecurePayloadClient
{
    public function __construct(
        private readonly SecurePayload $client,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
        private readonly string $baseUrl
    ) {
    }

    /**
     * @param array<string,mixed> $payload
     */
    public function post(string $uri, array $payload): string
    {
        $fullUrl = rtrim($this->baseUrl, '/') . '/' . ltrim($uri, '/');
        [$headers, $body] = $this->client->buildHeadersAndBody($fullUrl, 'POST', $payload);

        $request = $this->requestFactory->createRequest('POST', $fullUrl);
        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }
        $request = $request->withBody($this->streamFactory->createStream($body));

        $response = $this->httpClient->sendRequest($request);

        return (string) $response->getBody();
    }
}
