<?php
declare(strict_types=1);

namespace SecurePayload\Http;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

final class Psr18Transport implements HttpTransportInterface
{
    private ClientInterface $client;
    private RequestFactoryInterface $requestFactory;
    private StreamFactoryInterface $streamFactory;

    public function __construct(
        ClientInterface $client,
        RequestFactoryInterface $requestFactory,
        StreamFactoryInterface $streamFactory
    ) {
        $this->client = $client;
        $this->requestFactory = $requestFactory;
        $this->streamFactory = $streamFactory;
    }

    public function send(string $url, string $method, string $body, array $headers): array
    {
        $request = $this->requestFactory->createRequest(strtoupper($method), $url);
        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }
        if (!$request->hasHeader('Content-Type')) {
            $request = $request->withHeader('Content-Type', 'application/json');
        }
        $request = $request->withBody($this->streamFactory->createStream($body));

        $response = $this->client->sendRequest($request);

        $respHeaders = [];
        foreach ($response->getHeaders() as $name => $values) {
            $respHeaders[$name] = implode(', ', $values);
        }

        return HttpResponseParser::fromParts(
            $response->getStatusCode(),
            $respHeaders,
            (string) $response->getBody()
        );
    }
}
