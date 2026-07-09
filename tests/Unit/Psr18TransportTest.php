<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use SecurePayload\Http\Psr18Transport;

final class Psr18TransportTest extends TestCase
{
    public function testSendBuildsRequestWithHeadersAndBody(): void
    {
        $capturedMethod = null;
        $capturedUrl = null;
        $capturedHeaders = [];
        $capturedBody = null;

        $stream = $this->createMock(StreamInterface::class);
        $stream->method('__toString')->willReturn('{"ok":true}');

        $response = $this->createMock(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);
        $response->method('getHeaders')->willReturn(['Content-Type' => ['application/json']]);
        $response->method('getBody')->willReturn($stream);

        $request = $this->createMock(RequestInterface::class);
        $request->method('withHeader')->willReturnCallback(function (string $name, string $value) use (&$capturedHeaders, $request) {
            $capturedHeaders[$name] = $value;

            return $request;
        });
        $request->method('withBody')->willReturnCallback(function (StreamInterface $body) use (&$capturedBody, $request) {
            $capturedBody = $body;

            return $request;
        });
        $request->method('hasHeader')->with('Content-Type')->willReturn(false);

        $factory = $this->createMock(RequestFactoryInterface::class);
        $factory->method('createRequest')->willReturnCallback(function (string $method, $uri) use (&$capturedMethod, &$capturedUrl, $request) {
            $capturedMethod = $method;
            $capturedUrl = (string) $uri;

            return $request;
        });

        $streamFactory = $this->createMock(StreamFactoryInterface::class);
        $streamFactory->method('createStream')->with('{"a":1}')->willReturn($stream);

        $client = $this->createMock(ClientInterface::class);
        $client->expects($this->once())->method('sendRequest')->with($request)->willReturn($response);

        $transport = new Psr18Transport($client, $factory, $streamFactory);
        $result = $transport->send('https://api.test/v1', 'POST', '{"a":1}', ['X-Nonce' => 'n1']);

        $this->assertSame('POST', $capturedMethod);
        $this->assertSame('https://api.test/v1', $capturedUrl);
        $this->assertSame('n1', $capturedHeaders['X-Nonce']);
        $this->assertSame('application/json', $capturedHeaders['Content-Type']);
        $this->assertSame($stream, $capturedBody);
        $this->assertSame(200, $result['status']);
        $this->assertSame(['ok' => true], $result['body']);
        $this->assertNull($result['error']);
    }
}
