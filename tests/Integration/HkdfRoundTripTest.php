<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Integration;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

/**
 * Integrasi Phase 5 — round-trip dengan derivasi subkey HKDF aktif (`deriveKeys`).
 *
 * Memastikan request→response tetap konsisten saat client & server sama-sama
 * memakai master key + derivasi subkey per-fungsi, untuk semua mode.
 */
final class HkdfRoundTripTest extends TestCase
{
    private const HMAC_32 = 'test-hmac-secret-must-be-32bytes!!';

    private function aeadKeyB64(): string
    {
        return base64_encode(str_repeat("\x22", 32));
    }

    private function client(string $mode): SecurePayload
    {
        return new SecurePayload([
            'mode' => $mode,
            'deriveKeys' => true,
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::HMAC_32,
            'aeadKeyB64' => $this->aeadKeyB64(),
        ]);
    }

    private function server(string $mode): SecurePayload
    {
        return new SecurePayload([
            'mode' => $mode,
            'deriveKeys' => true,
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => $this->aeadKeyB64()],
        ]);
    }

    private function skipIfNoSodium(string $mode): void
    {
        if (($mode === 'aead' || $mode === 'both') && !extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium tidak tersedia');
        }
    }

    /** @return array<string,array{0:string}> */
    public static function modes(): array
    {
        return ['hmac' => ['hmac'], 'aead' => ['aead'], 'both' => ['both']];
    }

    /**
     * @dataProvider modes
     */
    public function testRequestRoundTrip(string $mode): void
    {
        $this->skipIfNoSodium($mode);

        $client = $this->client($mode);
        $server = $this->server($mode);

        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/data?b=2&a=1', 'POST', ['hello' => 'dunia']);
        $res = $server->verify($headers, $body, 'POST', '/v1/data', 'b=2&a=1');

        $this->assertTrue($res['ok'], "Round-trip request mode $mode dengan deriveKeys harus lolos.");
        $this->assertSame(['hello' => 'dunia'], $res['json']);
    }

    /**
     * @dataProvider modes
     */
    public function testResponseRoundTrip(string $mode): void
    {
        $this->skipIfNoSodium($mode);

        $client = $this->client($mode);
        $server = $this->server($mode);

        [$reqHeaders] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['ping' => 1]);
        [$respHeaders, $respBody] = $server->buildResponse($reqHeaders, ['amount' => 100]);

        $res = $client->verifyResponse($respHeaders, $respBody, $reqHeaders[SecurePayload::HX_NONCE]);
        $this->assertTrue($res['ok'], "Round-trip response mode $mode dengan deriveKeys harus lolos.");
        $this->assertSame(['amount' => 100], $res['json']);
    }
}
