<?php
declare(strict_types=1);

namespace SecurePayload\Tests;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

/**
 * Unit tests for the "verifySimple" API (headers + body only).
 */
final class VerifySimpleTest extends TestCase
{

    /**
     * Decode X-Canonical-Request from header.
     * Supports new Base64 form and legacy raw form with newlines.
     * @return array{0:string,1:string,2:string} [method, path, qStr]
     */
    private function canonPartsFromHeader(string $hdr): array
    {
        $canon = $hdr;
        if (strpos($canon, "\n") === false) {
            $decoded = base64_decode($canon, true);
            if (is_string($decoded) && $decoded !== '') {
                $canon = $decoded;
            }
        }
        $parts = explode("\n", $canon, 3);
        $this->assertCount(3, $parts, 'Bad canonical header format');
        return [$parts[0], $parts[1], $parts[2]];
    }

    public function testHmacVerifySimple(): void
    {
        $spClient = new SecurePayload([
            'mode' => 'hmac',
            'version' => '1',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => 'secret',
        ]);

        [$headers, $body] = $spClient->buildHeadersAndBody('https://api.example.com/api/foo', 'POST', ['a' => 1]);

        $keyLoader = function (string $cid, string $kid): array {
            return ['hmacSecret' => 'secret', 'aeadKeyB64' => null];
        };

        $spServer = new SecurePayload([
            'mode' => 'hmac',
            'version' => '1',
            'keyLoader' => $keyLoader,
        ]);

        $vr = $spServer->verifySimple($headers, $body, 'POST', '/api/foo');
        $this->assertTrue($vr['ok'] ?? false, json_encode($vr));
        $this->assertSame('HMAC', $vr['mode'] ?? null);
        $this->assertSame(['a' => 1], $vr['json'] ?? null);
    }

    public function testBothVerifySimple(): void
    {
        if (!\extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium is required for BOTH mode');
        }

        $aeadKey = base64_encode(random_bytes(32));

        $spClient = new SecurePayload([
            'mode' => 'both',
            'version' => '1',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => 'secret',
            'aeadKeyB64' => $aeadKey,
        ]);

        [$headers, $body] = $spClient->buildHeadersAndBody('https://api.example.com/v1/bar', 'PUT', ['x' => 'y']);

        $keyLoader = function (string $cid, string $kid) use ($aeadKey): array {
            return ['hmacSecret' => 'secret', 'aeadKeyB64' => $aeadKey];
        };

        $spServer = new SecurePayload([
            'mode' => 'both',
            'version' => '1',
            'keyLoader' => $keyLoader,
        ]);

        $vr = $spServer->verifySimple($headers, $body, 'PUT', '/v1/bar');
        $this->assertTrue($vr['ok'] ?? false, json_encode($vr));
        $this->assertSame('BOTH', $vr['mode'] ?? null);
        $this->assertSame(['x' => 'y'], $vr['json'] ?? null);
    }

    public function testAeadVerifySimple(): void
    {
        if (!\extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium is required for AEAD mode');
        }

        $aeadKey = base64_encode(random_bytes(32));

        $spClient = new SecurePayload([
            'mode' => 'aead',
            'version' => '1',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'aeadKeyB64' => $aeadKey,
        ]);

        [$headers, $body] = $spClient->buildHeadersAndBody('https://api.example.com/aead', 'PATCH', ['z' => 3]);

        $keyLoader = function (string $cid, string $kid) use ($aeadKey): array {
            return ['hmacSecret' => null, 'aeadKeyB64' => $aeadKey];
        };

        $spServer = new SecurePayload([
            'mode' => 'aead',
            'version' => '1',
            'keyLoader' => $keyLoader,
        ]);

        $vr = $spServer->verifySimple($headers, $body, 'PATCH', '/aead');
        $this->assertTrue($vr['ok'] ?? false, json_encode($vr));
        $this->assertSame('AEAD', $vr['mode'] ?? null);
        $this->assertSame(['z' => 3], $vr['json'] ?? null);
    }

    public function testVerifySimpleMissingCanonicalHeader(): void
    {
        $sp = new SecurePayload([
            'mode' => 'hmac',
            'version' => '1',
            'keyLoader' => fn(string $c, string $k) => ['hmacSecret' => 'secret', 'aeadKeyB64' => null],
        ]);

        $headers = []; // sengaja kosong
        $res = $sp->verifySimple($headers, '{}', 'GET', '/');
        $this->assertFalse($res['ok'] ?? true);
        $this->assertSame(400, $res['status'] ?? 0);
        $this->assertStringContainsString('Header keamanan tidak lengkap', $res['error'] ?? '');
    }
}
