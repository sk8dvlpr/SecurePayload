<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;
use SecurePayload\Exceptions\SecurePayloadException;

/**
 * Pengujian signing asimetris Ed25519 (signAlg='ed25519').
 *
 * Client menandatangani dengan secret key, server memverifikasi dengan public key.
 * Pesan kanonik yang ditandatangani identik dengan jalur HMAC (canonicalization
 * tidak berubah) — hanya algoritma tanda tangannya yang berbeda.
 */
final class Ed25519SigningTest extends TestCase
{
    private const HMAC_32 = 'test-hmac-secret-must-be-32bytes!!';

    /** @return array{publicB64:string, secretB64:string} */
    private function keypair(): array
    {
        $pair = sodium_crypto_sign_keypair();
        return [
            'publicB64' => base64_encode(sodium_crypto_sign_publickey($pair)),
            'secretB64' => base64_encode(sodium_crypto_sign_secretkey($pair)),
        ];
    }

    protected function setUp(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium required');
        }
    }

    public function testHmacModeEd25519HappyPath(): void
    {
        $kp = $this->keypair();

        $client = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'ed25519',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'ed25519SecretKeyB64' => $kp['secretB64'],
        ]);

        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/data?x=1', 'POST', ['a' => 1]);
        $this->assertSame(SecurePayload::ED25519_ALG, $headers[SecurePayload::HX_SIG_ALG]);

        $server = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'ed25519',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => null, 'aeadKeyB64' => null, 'ed25519PublicKeyB64' => $kp['publicB64']],
        ]);

        $res = $server->verify($headers, $body, 'POST', '/v1/data', ['x' => 1]);
        $this->assertTrue($res['ok'], $res['error'] ?? '');
        $this->assertSame('HMAC', $res['mode']);
        $this->assertSame(['a' => 1], $res['json']);
    }

    public function testBothModeEd25519HappyPath(): void
    {
        $kp = $this->keypair();
        $aeadKeyB64 = base64_encode(random_bytes(32));

        $client = new SecurePayload([
            'mode' => 'both',
            'signAlg' => 'ed25519',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'ed25519SecretKeyB64' => $kp['secretB64'],
            'aeadKeyB64' => $aeadKeyB64,
        ]);

        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['secret' => 'data']);
        $this->assertSame(SecurePayload::ED25519_ALG, $headers[SecurePayload::HX_SIG_ALG]);

        $server = new SecurePayload([
            'mode' => 'both',
            'signAlg' => 'ed25519',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => null, 'aeadKeyB64' => $aeadKeyB64, 'ed25519PublicKeyB64' => $kp['publicB64']],
        ]);

        $res = $server->verify($headers, $body, 'POST', '/v1/x', []);
        $this->assertTrue($res['ok'], $res['error'] ?? '');
        $this->assertSame('BOTH', $res['mode']);
        $this->assertSame(['secret' => 'data'], $res['json']);
    }

    public function testTamperedSignatureRejected(): void
    {
        $kp = $this->keypair();

        $client = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'ed25519',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'ed25519SecretKeyB64' => $kp['secretB64'],
        ]);
        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/data', 'POST', ['a' => 1]);

        // Rusak signature dengan signature acak berukuran benar.
        $headers[SecurePayload::HX_SIGNATURE] = base64_encode(random_bytes(SODIUM_CRYPTO_SIGN_BYTES));

        $server = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'ed25519',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => null, 'aeadKeyB64' => null, 'ed25519PublicKeyB64' => $kp['publicB64']],
        ]);

        $res = $server->verify($headers, $body, 'POST', '/v1/data', []);
        $this->assertFalse($res['ok']);
        $this->assertStringContainsString('Ed25519', $res['error']);
    }

    public function testWrongPublicKeyRejected(): void
    {
        $clientKp = $this->keypair();
        $otherKp = $this->keypair();

        $client = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'ed25519',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'ed25519SecretKeyB64' => $clientKp['secretB64'],
        ]);
        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/data', 'POST', ['a' => 1]);

        $server = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'ed25519',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => null, 'aeadKeyB64' => null, 'ed25519PublicKeyB64' => $otherKp['publicB64']],
        ]);

        $res = $server->verify($headers, $body, 'POST', '/v1/data', []);
        $this->assertFalse($res['ok']);
    }

    public function testServerMissingPublicKeyReturnsServerError(): void
    {
        $kp = $this->keypair();

        $client = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'ed25519',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'ed25519SecretKeyB64' => $kp['secretB64'],
        ]);
        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/data', 'POST', ['a' => 1]);

        $server = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'ed25519',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => null, 'aeadKeyB64' => null, 'ed25519PublicKeyB64' => null],
        ]);

        $res = $server->verify($headers, $body, 'POST', '/v1/data', []);
        $this->assertFalse($res['ok']);
        $this->assertSame(500, $res['status']);
        $this->assertStringContainsString('Public key Ed25519', $res['error']);
    }

    public function testConstructorRejectsInvalidSecretKeyLength(): void
    {
        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionMessage('Secret key Ed25519 tidak valid');
        new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'ed25519',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'ed25519SecretKeyB64' => base64_encode('too-short'),
        ]);
    }

    public function testConstructorRejectsInvalidSignAlg(): void
    {
        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionMessage('signAlg tidak valid');
        new SecurePayload(['mode' => 'hmac', 'signAlg' => 'rsa']);
    }
}
