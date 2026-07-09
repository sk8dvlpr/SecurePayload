<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;
use SecurePayload\Exceptions\SecurePayloadException;

/**
 * Pengujian Ed25519 response signing (Phase 9).
 *
 * signAlg mirror: server menandatangani response dengan keypair server;
 * client memverifikasi dengan public key server — tanpa HMAC secret bersama.
 */
final class Ed25519ResponseSigningTest extends TestCase
{
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

    public function testHmacModeEd25519ResponseRoundTrip(): void
    {
        $clientKp = $this->keypair();
        $serverKp = $this->keypair();

        $client = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'ed25519',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'ed25519SecretKeyB64' => $clientKp['secretB64'],
            'ed25519PublicKeyServerB64' => $serverKp['publicB64'],
        ]);
        [$reqHeaders] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['ping' => 1]);

        $server = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'ed25519',
            'keyLoader' => fn($c, $k) => [
                'hmacSecret' => null,
                'aeadKeyB64' => null,
                'ed25519PublicKeyB64' => $clientKp['publicB64'],
                'ed25519SecretKeyServerB64' => $serverKp['secretB64'],
            ],
        ]);
        [$respHeaders, $respBody] = $server->buildResponse($reqHeaders, ['pong' => true]);
        $this->assertSame(SecurePayload::ED25519_ALG, $respHeaders[SecurePayload::HX_RESP_SIG_ALG]);

        $res = $client->verifyResponse($respHeaders, $respBody, $reqHeaders[SecurePayload::HX_NONCE]);
        $this->assertTrue($res['ok'], $res['error'] ?? '');
        $this->assertSame(['pong' => true], $res['json']);
    }

    public function testBothModeEd25519ResponseRoundTrip(): void
    {
        $clientKp = $this->keypair();
        $serverKp = $this->keypair();
        $aeadKeyB64 = base64_encode(random_bytes(32));

        $client = new SecurePayload([
            'mode' => 'both',
            'signAlg' => 'ed25519',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'ed25519SecretKeyB64' => $clientKp['secretB64'],
            'ed25519PublicKeyServerB64' => $serverKp['publicB64'],
            'aeadKeyB64' => $aeadKeyB64,
        ]);
        [$reqHeaders] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['secret' => 'data']);

        $server = new SecurePayload([
            'mode' => 'both',
            'signAlg' => 'ed25519',
            'keyLoader' => fn($c, $k) => [
                'hmacSecret' => null,
                'aeadKeyB64' => $aeadKeyB64,
                'ed25519PublicKeyB64' => $clientKp['publicB64'],
                'ed25519SecretKeyServerB64' => $serverKp['secretB64'],
            ],
        ]);
        [$respHeaders, $respBody] = $server->buildResponse($reqHeaders, ['data' => 'aman']);
        $this->assertStringNotContainsString('aman', $respBody);
        $this->assertSame(SecurePayload::ED25519_ALG, $respHeaders[SecurePayload::HX_RESP_SIG_ALG]);

        $res = $client->verifyResponse($respHeaders, $respBody, $reqHeaders[SecurePayload::HX_NONCE]);
        $this->assertTrue($res['ok'], $res['error'] ?? '');
        $this->assertSame('BOTH', $res['mode']);
        $this->assertSame(['data' => 'aman'], $res['json']);
    }

    public function testClientWithoutHmacSecretVerifiesEd25519Response(): void
    {
        $clientKp = $this->keypair();
        $serverKp = $this->keypair();

        $client = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'ed25519',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'ed25519SecretKeyB64' => $clientKp['secretB64'],
            'ed25519PublicKeyServerB64' => $serverKp['publicB64'],
        ]);
        [$reqHeaders] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['x' => 1]);

        $server = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'ed25519',
            'keyLoader' => fn($c, $k) => [
                'ed25519PublicKeyB64' => $clientKp['publicB64'],
                'ed25519SecretKeyServerB64' => $serverKp['secretB64'],
            ],
        ]);
        [$respHeaders, $respBody] = $server->buildResponse($reqHeaders, ['ok' => 1]);

        $res = $client->verifyResponse($respHeaders, $respBody, $reqHeaders[SecurePayload::HX_NONCE]);
        $this->assertTrue($res['ok'], $res['error'] ?? '');
    }

    public function testTamperedEd25519ResponseSignatureRejected(): void
    {
        $clientKp = $this->keypair();
        $serverKp = $this->keypair();

        $client = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'ed25519',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'ed25519SecretKeyB64' => $clientKp['secretB64'],
            'ed25519PublicKeyServerB64' => $serverKp['publicB64'],
        ]);
        [$reqHeaders] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['a' => 1]);

        $server = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'ed25519',
            'keyLoader' => fn($c, $k) => [
                'ed25519PublicKeyB64' => $clientKp['publicB64'],
                'ed25519SecretKeyServerB64' => $serverKp['secretB64'],
            ],
        ]);
        [$respHeaders, $respBody] = $server->buildResponse($reqHeaders, ['amount' => 100]);

        $respHeaders[SecurePayload::HX_RESP_SIGNATURE] = base64_encode(random_bytes(SODIUM_CRYPTO_SIGN_BYTES));

        $res = $client->verifyResponse($respHeaders, $respBody, $reqHeaders[SecurePayload::HX_NONCE]);
        $this->assertFalse($res['ok']);
        $this->assertStringContainsString('Ed25519', $res['error']);
    }

    public function testWrongServerPublicKeyRejected(): void
    {
        $clientKp = $this->keypair();
        $serverKp = $this->keypair();
        $otherServerKp = $this->keypair();

        $client = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'ed25519',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'ed25519SecretKeyB64' => $clientKp['secretB64'],
            'ed25519PublicKeyServerB64' => $otherServerKp['publicB64'],
        ]);
        [$reqHeaders] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['a' => 1]);

        $server = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'ed25519',
            'keyLoader' => fn($c, $k) => [
                'ed25519PublicKeyB64' => $clientKp['publicB64'],
                'ed25519SecretKeyServerB64' => $serverKp['secretB64'],
            ],
        ]);
        [$respHeaders, $respBody] = $server->buildResponse($reqHeaders, ['amount' => 100]);

        $res = $client->verifyResponse($respHeaders, $respBody, $reqHeaders[SecurePayload::HX_NONCE]);
        $this->assertFalse($res['ok']);
    }

    public function testAntiDowngradeHmacResponseRejectedWhenSignAlgEd25519(): void
    {
        $clientKp = $this->keypair();
        $serverKp = $this->keypair();
        $hmac = 'test-hmac-secret-must-be-32bytes!!';

        $client = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'ed25519',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'ed25519SecretKeyB64' => $clientKp['secretB64'],
            'ed25519PublicKeyServerB64' => $serverKp['publicB64'],
        ]);
        [$reqHeaders] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['a' => 1]);

        // Server dengan signAlg=hmac menghasilkan response HMAC.
        $serverHmac = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'hmac',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => $hmac, 'aeadKeyB64' => null],
        ]);
        [$respHeaders, $respBody] = $serverHmac->buildResponse($reqHeaders, ['ok' => 1]);
        $this->assertSame(SecurePayload::HMAC_ALG, $respHeaders[SecurePayload::HX_RESP_SIG_ALG]);

        $res = $client->verifyResponse($respHeaders, $respBody, $reqHeaders[SecurePayload::HX_NONCE]);
        $this->assertFalse($res['ok']);
        $this->assertStringContainsString('salah algoritma', $res['error']);
    }

    public function testConstructorRejectsInvalidServerPublicKeyLength(): void
    {
        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionMessage('Public key Ed25519 server tidak valid');
        new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'ed25519',
            'ed25519PublicKeyServerB64' => base64_encode('too-short'),
        ]);
    }
}
