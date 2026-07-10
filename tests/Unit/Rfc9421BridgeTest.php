<?php

declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\Interop\Rfc9421Bridge;
use SecurePayload\SecurePayload;

final class Rfc9421BridgeTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    public function testExportAndVerifyMappedRoundTrip(): void
    {
        $clock = static fn (): int => 1_700_000_000;
        $client = new SecurePayload([
            'mode' => 'hmac',
            'version' => '3',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::SECRET,
            'clock' => $clock,
            'nonceGenerator' => static fn (): string => base64_encode(str_repeat("\x02", 16)),
        ]);
        $server = new SecurePayload([
            'mode' => 'hmac',
            'version' => '3',
            'clock' => $clock,
            'replayStore' => static fn (string $k, int $t): bool => true,
            'keyLoader' => static fn (): array => ['hmacSecret' => self::SECRET, 'aeadKeyB64' => null],
        ]);

        [$spHeaders, $body] = $client->buildHeadersAndBody(
            'https://api.test/hook?a=1',
            'POST',
            ['hello' => 'world']
        );

        $rfc = Rfc9421Bridge::exportFromSecureHeaders($spHeaders, 'POST', '/hook', 'a=1', $body);

        $this->assertArrayHasKey('Signature-Input', $rfc);
        $this->assertArrayHasKey('Signature', $rfc);
        $this->assertArrayHasKey('Content-Digest', $rfc);
        $this->assertStringContainsString('"@method"', $rfc['Signature-Input']);
        $this->assertStringContainsString('"content-digest"', $rfc['Signature-Input']);
        $this->assertStringStartsWith('sha-256=:', $rfc['Content-Digest']);

        $result = Rfc9421Bridge::verifyMapped($server, $rfc, $body, 'POST', '/hook', 'a=1');
        $this->assertTrue($result['ok'], $result['error'] ?? '');
        $this->assertSame(['hello' => 'world'], $result['json']);
    }

    public function testVerifyMappedFailsOnBadContentDigest(): void
    {
        $clock = static fn (): int => 1_700_000_000;
        $client = new SecurePayload([
            'mode' => 'hmac',
            'version' => '3',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::SECRET,
            'clock' => $clock,
            'nonceGenerator' => static fn (): string => base64_encode(str_repeat("\x03", 16)),
        ]);
        $server = new SecurePayload([
            'mode' => 'hmac',
            'version' => '3',
            'clock' => $clock,
            'replayStore' => static fn (string $k, int $t): bool => true,
            'keyLoader' => static fn (): array => ['hmacSecret' => self::SECRET, 'aeadKeyB64' => null],
        ]);

        [$spHeaders, $body] = $client->buildHeadersAndBody(
            'https://api.test/hook',
            'POST',
            ['x' => 1]
        );
        $rfc = Rfc9421Bridge::exportFromSecureHeaders($spHeaders, 'POST', '/hook', '', $body);
        $rfc['Content-Digest'] = 'sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:';

        $result = Rfc9421Bridge::verifyMapped($server, $rfc, $body, 'POST', '/hook', '');
        $this->assertFalse($result['ok']);
        $this->assertStringContainsString('Content-Digest', $result['error'] ?? '');
    }

    public function testVerifyMappedFailsOnMissingComponent(): void
    {
        $server = new SecurePayload([
            'mode' => 'hmac',
            'version' => '3',
            'clock' => static fn (): int => 1_700_000_000,
            'replayStore' => static fn (string $k, int $t): bool => true,
            'keyLoader' => static fn (): array => ['hmacSecret' => self::SECRET, 'aeadKeyB64' => null],
        ]);

        $headers = [
            'Signature-Input' => 'sp1=("@method" "@path");created=1;alg="hmac-sha256"',
            'Content-Digest' => 'sha-256=:' . base64_encode(hash('sha256', '{}', true)) . ':',
        ];
        $result = Rfc9421Bridge::verifyMapped($server, $headers, '{}', 'POST', '/', '');
        $this->assertFalse($result['ok']);
        $this->assertStringContainsString('komponen wajib', $result['error'] ?? '');
    }
}
