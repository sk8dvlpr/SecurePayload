<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Security;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

/**
 * Regresi keamanan untuk downgrade algoritma tanda tangan.
 *
 * Server menentukan algoritma dari konfigurasinya sendiri (signAlg), BUKAN dari
 * header X-Signature-Algorithm. Maka:
 *  - server bermode ed25519 harus menolak request bertanda tangan HMAC, dan
 *  - server bermode hmac harus menolak request bertanda tangan ed25519,
 * meskipun penyerang memiliki salah satu kredensial.
 */
final class SignatureAlgDowngradeTest extends TestCase
{
    private const HMAC_32 = 'test-hmac-secret-must-be-32bytes!!';

    protected function setUp(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium required');
        }
    }

    /** @return array{publicB64:string, secretB64:string} */
    private function keypair(): array
    {
        $pair = sodium_crypto_sign_keypair();
        return [
            'publicB64' => base64_encode(sodium_crypto_sign_publickey($pair)),
            'secretB64' => base64_encode(sodium_crypto_sign_secretkey($pair)),
        ];
    }

    public function testEd25519ServerRejectsHmacSignedRequest(): void
    {
        $kp = $this->keypair();

        // Penyerang membuat request HMAC-only.
        $attacker = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'hmac',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::HMAC_32,
        ]);
        [$headers, $body] = $attacker->buildHeadersAndBody('https://api/v1/x', 'POST', ['amount' => 9999]);
        $this->assertSame(SecurePayload::HMAC_ALG, $headers[SecurePayload::HX_SIG_ALG]);

        // Server hanya menerima Ed25519.
        $server = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'ed25519',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null, 'ed25519PublicKeyB64' => $kp['publicB64']],
        ]);

        $res = $server->verify($headers, $body, 'POST', '/v1/x', []);
        $this->assertFalse($res['ok'], 'Server ed25519 menerima tanda tangan HMAC (downgrade!).');
        $this->assertStringContainsString('salah algoritma', $res['error']);
    }

    public function testHmacServerRejectsEd25519SignedRequest(): void
    {
        $kp = $this->keypair();

        $attacker = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'ed25519',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'ed25519SecretKeyB64' => $kp['secretB64'],
        ]);
        [$headers, $body] = $attacker->buildHeadersAndBody('https://api/v1/x', 'POST', ['a' => 1]);
        $this->assertSame(SecurePayload::ED25519_ALG, $headers[SecurePayload::HX_SIG_ALG]);

        $server = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => 'hmac',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null, 'ed25519PublicKeyB64' => $kp['publicB64']],
        ]);

        $res = $server->verify($headers, $body, 'POST', '/v1/x', []);
        $this->assertFalse($res['ok'], 'Server hmac menerima tanda tangan Ed25519.');
        $this->assertStringContainsString('salah algoritma', $res['error']);
    }
}
