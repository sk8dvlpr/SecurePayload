<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\Http\HttpTransportInterface;
use SecurePayload\SecurePayload;

final class SecurePayloadSendTransportTest extends TestCase
{
    private const HMAC_32 = 'test-hmac-secret-must-be-32bytes!!';

    public function testSendUsesInjectedTransportWithoutCurl(): void
    {
        $transport = new class implements HttpTransportInterface {
            public function send(string $url, string $method, string $body, array $headers): array
            {
                return [
                    'status' => 201,
                    'headers' => ['X-Test' => '1'],
                    'body' => ['echo' => json_decode($body, true)],
                    'error' => null,
                ];
            }
        };

        $client = new SecurePayload([
            'mode' => 'hmac',
            'version' => '3',
            'clientId' => 'transport-client',
            'keyId' => 'key-1',
            'hmacSecretRaw' => self::HMAC_32,
            'httpTransport' => $transport,
        ]);

        $result = $client->send('https://api.test/v1/pay', 'POST', ['amount' => 100]);

        $this->assertSame(201, $result['status']);
        $this->assertSame('1', $result['headers']['X-Test']);
        $this->assertIsArray($result['body']['echo']);
        $this->assertNull($result['error']);
    }

    public function testSendUsesCallableTransportFactory(): void
    {
        $client = new SecurePayload([
            'mode' => 'hmac',
            'version' => '3',
            'clientId' => 'transport-client',
            'keyId' => 'key-1',
            'hmacSecretRaw' => self::HMAC_32,
            'httpTransport' => static fn (): HttpTransportInterface => new class implements HttpTransportInterface {
                public function send(string $url, string $method, string $body, array $headers): array
                {
                    return [
                        'status' => 200,
                        'headers' => [],
                        'body' => 'ok',
                        'error' => null,
                    ];
                }
            },
        ]);

        $result = $client->send('https://api.test/x', 'GET', []);
        $this->assertSame(200, $result['status']);
        $this->assertSame('ok', $result['body']);
    }

    public function testSendThrowsWhenNoTransportAndNoCurl(): void
    {
        if (extension_loaded('curl')) {
            $this->markTestSkipped('Test hanya relevan saat ext-curl tidak tersedia');
        }

        $client = new SecurePayload([
            'mode' => 'hmac',
            'version' => '3',
            'clientId' => 'transport-client',
            'keyId' => 'key-1',
            'hmacSecretRaw' => self::HMAC_32,
        ]);

        $this->expectException(\SecurePayload\Exceptions\SecurePayloadException::class);
        $client->send('https://api.test/x', 'POST', []);
    }
}
