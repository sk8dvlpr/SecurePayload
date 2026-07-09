<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\Observability\OpenTelemetrySecurityExporter;
use SecurePayload\SecurePayload;
use SecurePayload\Webhook\WebhookVerifier;

final class WebhookVerifierTest extends TestCase
{
    private const HMAC_SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    public function testReadHeadersFromServerNginxStyle(): void
    {
        $headers = WebhookVerifier::readHeadersFromServer([
            'HTTP_X_CLIENT_ID' => 'client1',
            'HTTP_X_KEY_ID' => 'key1',
            'CONTENT_TYPE' => 'application/json',
        ]);

        $this->assertSame('client1', $headers['X-CLIENT-ID'] ?? $headers['X-Client-Id'] ?? null);
        $this->assertArrayHasKey('Content-Type', $headers);
    }

    public function testVerifyFromGlobalsDelegatesToVerify(): void
    {
        $client = new SecurePayload([
            'mode' => 'hmac',
            'version' => '3',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::HMAC_SECRET,
            'clock' => static fn (): int => 1_700_000_000,
            'nonceGenerator' => static fn (): string => base64_encode(str_repeat("\x01", 16)),
        ]);

        $server = new SecurePayload([
            'mode' => 'hmac',
            'version' => '3',
            'keyLoader' => static fn (): array => ['hmacSecret' => self::HMAC_SECRET],
            'clock' => static fn (): int => 1_700_000_000,
            'replayStore' => static fn (): bool => true,
        ]);

        [$headers, $body] = $client->buildHeadersAndBody('https://api.test/v1/hook', 'POST', ['ok' => true]);

        $verifier = new WebhookVerifier($server);
        $result = $verifier->verifyFromGlobals([
            'REQUEST_METHOD' => 'POST',
            'REQUEST_URI' => '/v1/hook',
        ], $body, static fn (): array => $headers);

        $this->assertTrue($result['ok']);
        $this->assertSame(['ok' => true], $result['json']);
    }

    public function testVerifyFromRequestWithQueryString(): void
    {
        $client = new SecurePayload([
            'mode' => 'hmac',
            'version' => '3',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::HMAC_SECRET,
            'clock' => static fn (): int => 1_700_000_000,
            'nonceGenerator' => static fn (): string => base64_encode(str_repeat("\x02", 16)),
        ]);

        $server = new SecurePayload([
            'mode' => 'hmac',
            'version' => '3',
            'keyLoader' => static fn (): array => ['hmacSecret' => self::HMAC_SECRET],
            'clock' => static fn (): int => 1_700_000_000,
            'replayStore' => static fn (): bool => true,
        ]);

        [$headers, $body] = $client->buildHeadersAndBody('https://api.test/v1/hook?a=1&b=2', 'POST', ['x' => 1]);

        $verifier = new WebhookVerifier($server);
        $result = $verifier->verifyFromRequest($headers, $body, 'POST', '/v1/hook', 'a=1&b=2');

        $this->assertTrue($result['ok']);
    }
}
