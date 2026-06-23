<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Integration;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

/**
 * Round-trip lengkap pengamanan RESPONSE (Phase 2):
 * client kirim request -> server buildResponse -> client verifyResponse.
 *
 * Diuji untuk ketiga mode (hmac/aead/both). Response diikat ke nonce request asal.
 */
final class ResponseRoundTripTest extends TestCase
{
    private const HMAC_32 = 'test-hmac-secret-must-be-32bytes!!';

    private function aeadKeyB64(): string
    {
        return base64_encode(str_repeat("\x11", 32));
    }

    public function testHmacResponseRoundTrip(): void
    {
        $client = new SecurePayload([
            'mode' => 'hmac',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::HMAC_32,
        ]);
        [$reqHeaders] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['ping' => 1]);

        $server = new SecurePayload([
            'mode' => 'hmac',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null],
        ]);
        [$respHeaders, $respBody] = $server->buildResponse($reqHeaders, ['pong' => true, 'val' => 42]);

        $res = $client->verifyResponse($respHeaders, $respBody, $reqHeaders[SecurePayload::HX_NONCE]);
        $this->assertTrue($res['ok'], $res['error'] ?? '');
        $this->assertSame('HMAC', $res['mode']);
        $this->assertSame(['pong' => true, 'val' => 42], $res['json']);
    }

    public function testAeadResponseRoundTrip(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium required');
        }
        $aead = $this->aeadKeyB64();

        $client = new SecurePayload([
            'mode' => 'aead',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'aeadKeyB64' => $aead,
        ]);
        [$reqHeaders] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['ping' => 1]);

        $server = new SecurePayload([
            'mode' => 'aead',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => null, 'aeadKeyB64' => $aead],
        ]);
        [$respHeaders, $respBody] = $server->buildResponse($reqHeaders, ['secret' => 'rahasia']);

        // Body response harus terenkripsi (tidak memuat plaintext).
        $this->assertStringNotContainsString('rahasia', $respBody);

        $res = $client->verifyResponse($respHeaders, $respBody, $reqHeaders[SecurePayload::HX_NONCE]);
        $this->assertTrue($res['ok'], $res['error'] ?? '');
        $this->assertSame('AEAD', $res['mode']);
        $this->assertSame(['secret' => 'rahasia'], $res['json']);
    }

    public function testBothResponseRoundTrip(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium required');
        }
        $aead = $this->aeadKeyB64();

        $client = new SecurePayload([
            'mode' => 'both',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::HMAC_32,
            'aeadKeyB64' => $aead,
        ]);
        [$reqHeaders] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['ping' => 1]);

        $server = new SecurePayload([
            'mode' => 'both',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => $aead],
        ]);
        [$respHeaders, $respBody] = $server->buildResponse($reqHeaders, ['data' => 'aman']);

        $this->assertStringNotContainsString('aman', $respBody);

        $res = $client->verifyResponse($respHeaders, $respBody, $reqHeaders[SecurePayload::HX_NONCE]);
        $this->assertTrue($res['ok'], $res['error'] ?? '');
        $this->assertSame('BOTH', $res['mode']);
        $this->assertSame(['data' => 'aman'], $res['json']);
    }

    public function testResponseWorksWithoutKeyLoaderUsingInstanceKeys(): void
    {
        // Server tanpa keyLoader: buildResponse jatuh ke kunci instance.
        $aead = $this->aeadKeyB64();
        $client = new SecurePayload([
            'mode' => 'both',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::HMAC_32,
            'aeadKeyB64' => $aead,
        ]);
        [$reqHeaders] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['ping' => 1]);

        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium required');
        }

        $server = new SecurePayload([
            'mode' => 'both',
            'hmacSecretRaw' => self::HMAC_32,
            'aeadKeyB64' => $aead,
        ]);
        [$respHeaders, $respBody] = $server->buildResponse($reqHeaders, ['ok' => 1]);

        $res = $client->verifyResponse($respHeaders, $respBody, $reqHeaders[SecurePayload::HX_NONCE]);
        $this->assertTrue($res['ok'], $res['error'] ?? '');
    }
}
