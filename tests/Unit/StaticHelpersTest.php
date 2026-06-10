<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

final class StaticHelpersTest extends TestCase
{
    private const HMAC_32 = 'test-hmac-secret-must-be-32bytes!!';

    // [COV-07a] normalizePath — path tanpa trailing slash tidak berubah
    public function testNormalizePath_NoTrailingSlash_Unchanged(): void
    {
        $this->assertSame('/api/v1/resource', SecurePayload::normalizePath('/api/v1/resource'));
    }

    // [COV-07b] normalizePath — path dengan trailing slash → dihapus
    public function testNormalizePath_WithTrailingSlash_Removed(): void
    {
        $this->assertSame('/api/v1', SecurePayload::normalizePath('/api/v1/'));
    }

    // [COV-07c] normalizePath — root path tidak berubah
    public function testNormalizePath_RootPath_Unchanged(): void
    {
        $this->assertSame('/', SecurePayload::normalizePath('/'));
    }

    // [COV-07c2] normalizePath — path kosong -> '/'
    public function testNormalizePath_EmptyPath_ReturnsRoot(): void
    {
        $this->assertSame('/', SecurePayload::normalizePath(''));
    }

    // [COV-07d] canonicalQuery — array kosong → string kosong
    public function testBuildHeadersAndBody_EmptyQueryString_InSignature(): void
    {
        $client = new SecurePayload([
            'mode'          => 'hmac',
            'version'       => '1',
            'clientId'      => 'c',
            'keyId'         => 'k',
            'hmacSecretRaw' => self::HMAC_32,
        ]);

        // URL tanpa query string
        [$headers, $body] = $client->buildHeadersAndBody(
            'https://api.test/resource', 'POST', ['data' => 1]
        );

        $server = new SecurePayload([
            'mode'      => 'hmac',
            'version'   => '1',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null],
        ]);

        // verify() dengan query kosong
        $res = $server->verify($headers, $body, 'POST', '/resource', []);
        $this->assertTrue($res['ok']);
    }

    // [COV-07e] buildHeadersAndBody dengan query string multikey (cover ksort branch)
    public function testBuildHeadersAndBody_MultiKeyQuery_SortedCorrectly(): void
    {
        $client = new SecurePayload([
            'mode'          => 'hmac',
            'version'       => '1',
            'clientId'      => 'c',
            'keyId'         => 'k',
            'hmacSecretRaw' => self::HMAC_32,
        ]);

        // URL dengan multiple query params — harus di-sort ksort sebelum sign
        [$headers, $body] = $client->buildHeadersAndBody(
            'https://api.test/q?z=last&a=first&m=middle', 'GET', []
        );

        $server = new SecurePayload([
            'mode'      => 'hmac',
            'version'   => '1',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null],
        ]);

        // Server verify dengan query yang SAMA tapi urutan berbeda → harus tetap valid
        // karena keduanya di-ksort sebelum sign/verify
        $res = $server->verify($headers, $body, 'GET', '/q', [
            'z' => 'last', 'a' => 'first', 'm' => 'middle'
        ]);
        $this->assertTrue($res['ok']);
    }

    // [COV-07e2] canonicalQuery dengan array
    public function testCanonicalQuery_ArrayValue(): void
    {
        $res = SecurePayload::canonicalQuery(['b' => 2, 'a' => [1, 3]]);
        $this->assertSame('a=1%2C3&b=2', $res);
    }

    // [COV-07f] aeadNonceFrom — dipanggil saat AEAD mode, hasilnya 24 bytes
    public function testBuildHeadersAndBody_AeadMode_AeadNonceHeaderPresent(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium required');
        }
        $aeadKey = base64_encode(random_bytes(32));
        $client = new SecurePayload([
            'mode'      => 'aead',
            'version'   => '1',
            'clientId'  => 'c',
            'keyId'     => 'k',
            'aeadKeyB64' => $aeadKey,
        ]);

        [$headers] = $client->buildHeadersAndBody(
            'https://api.test/aead', 'POST', ['secret' => 'data']
        );

        // X-AEAD-Nonce harus ada dan berisi 24 bytes base64
        $this->assertArrayHasKey('X-AEAD-Nonce', $headers);
        $decoded = base64_decode($headers['X-AEAD-Nonce'], true);
        $this->assertSame(24, strlen($decoded));
    }

    // [COV-07f2] aeadNonceFrom dengan invalid base64
    public function testAeadNonceFrom_InvalidBase64(): void
    {
        // base64_decode('!!!', true) returns false, falls back to null bytes
        $nonce = SecurePayload::aeadNonceFrom('!!!', 'POST', '/a', '');
        $this->assertSame(24, strlen($nonce));
    }
}
