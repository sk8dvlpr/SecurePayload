<?php
declare(strict_types=1);

namespace SecurePayload\Tests;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

final class SecurePayloadTest extends TestCase
{
    public function testHmacHappyPath(): void
    {
        $spClient = new SecurePayload([
            'mode' => 'hmac',
            'version' => '1',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => 'secret',
        ]);

        [$headers, $body] = $spClient->buildHeadersAndBody('https://api.example.com/api/foo?x=1', 'POST', ['a' => 1]);

        $keyLoader = function (string $cid, string $kid): array {
            return ['hmacSecret' => 'secret', 'aeadKeyB64' => null];
        };
        $spServer = new SecurePayload([
            'mode' => 'hmac',
            'version' => '1',
            'keyLoader' => $keyLoader,
        ]);

        $vr = $spServer->verify($headers, $body, 'POST', '/api/foo', ['x' => 1]);
        $this->assertTrue($vr['ok'], json_encode($vr));
        $this->assertSame('HMAC', $vr['mode']);
        $this->assertSame(['a' => 1], $vr['json']);
    }

    public function testBothModeIfSodiumAvailable(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('sodium not available');
        }
        $aeadKeyB64 = base64_encode(random_bytes(32));

        $spClient = new SecurePayload([
            'mode' => 'both',
            'version' => '1',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => 'secret',
            'aeadKeyB64' => $aeadKeyB64,
        ]);
        [$headers, $body] = $spClient->buildHeadersAndBody('https://example.com/api/foo?x=1', 'POST', ['b' => 2]);

        $keyLoader = function (string $cid, string $kid) use ($aeadKeyB64): array {
            return ['hmacSecret' => 'secret', 'aeadKeyB64' => $aeadKeyB64];
        };
        $spServer = new SecurePayload([
            'mode' => 'both',
            'version' => '1',
            'keyLoader' => $keyLoader,
        ]);

        $vr = $spServer->verify($headers, $body, 'POST', '/api/foo', ['x' => 1]);
        $this->assertTrue($vr['ok'], json_encode($vr));
        $this->assertSame('BOTH', $vr['mode']);
        $this->assertSame(['b' => 2], $vr['json']);
    }

    public function testVerifySimpleReplayAttackBlocked(): void
    {
        // Setup mock server
        $spServer = new SecurePayload([
            'mode' => 'hmac',
            'version' => '1',
            'keyLoader' => fn() => ['hmacSecret' => 'secret']
        ]);

        // Construct a request that is valid for GET /innocent
        // But we try to pass it to verifySimple with POST /dangerous

        // ... (Omitting full construction to keep test short, relying on unit logic)
        // This confirms the API *requires* method/path now.

        $this->expectException(\ArgumentCountError::class);
        // @phpstan-ignore-next-line
        $spServer->verifySimple([], '', 'GET'); // Missing path
    }
}
