<?php

declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\Crypto\PqSignerInterface;
use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\SecurePayload;

/**
 * Stub ML-DSA untuk uji format wire saja — BUKAN kriptografi post-quantum nyata.
 * Signature deterministik: SHA-512(msg) diulang/dipotong ke 2420 byte.
 */
final class FakeMldsa44Signer implements PqSignerInterface
{
    public function sign(string $msg): string
    {
        $seed = hash('sha512', 'fake-mldsa|' . $msg, true);
        return str_pad($seed, self::MLDSA44_SIG_BYTES, $seed);
    }

    public function verify(string $msg, string $sig, string $publicKey): bool
    {
        return hash_equals($this->sign($msg), $sig) && $publicKey !== '';
    }
}

final class HybridSignAlgTest extends TestCase
{
    protected function setUp(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium diperlukan');
        }
    }

    public function testHybridRequiresPqSigner(): void
    {
        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionMessage('pqSigner');
        new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => SecurePayload::SIGN_ALG_HYBRID,
            'version' => '4',
        ]);
    }

    public function testHybridRequestRoundTrip(): void
    {
        $kp = sodium_crypto_sign_keypair();
        $sk = sodium_crypto_sign_secretkey($kp);
        $pk = sodium_crypto_sign_publickey($kp);
        $mldsaPub = str_repeat("\x11", PqSignerInterface::MLDSA44_PUBLIC_BYTES);
        $signer = new FakeMldsa44Signer();
        $clock = static fn (): int => 1_700_000_000;

        $client = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => SecurePayload::SIGN_ALG_HYBRID,
            'version' => '4',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'ed25519SecretKeyB64' => base64_encode($sk),
            'mldsaPublicKeyB64' => base64_encode($mldsaPub),
            'pqSigner' => $signer,
            'clock' => $clock,
            'nonceGenerator' => static fn (): string => base64_encode(str_repeat("\x0c", 16)),
        ]);
        $server = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => SecurePayload::SIGN_ALG_HYBRID,
            'version' => '4',
            'pqSigner' => $signer,
            'mldsaPublicKeyB64' => base64_encode($mldsaPub),
            'clock' => $clock,
            'replayStore' => static fn (string $k, int $t): bool => true,
            'keyLoader' => static function () use ($pk, $mldsaPub): array {
                return [
                    'hmacSecret' => null,
                    'aeadKeyB64' => null,
                    'ed25519PublicKeyB64' => base64_encode($pk),
                    'mldsaPublicKeyB64' => base64_encode($mldsaPub),
                ];
            },
        ]);

        [$headers, $body] = $client->buildHeadersAndBody(
            'https://api.test/hq',
            'POST',
            ['pq' => true]
        );

        $this->assertSame(SecurePayload::HYBRID_ALG, $headers[SecurePayload::HX_SIG_ALG]);
        $raw = base64_decode($headers[SecurePayload::HX_SIGNATURE], true);
        $this->assertIsString($raw);
        $this->assertSame(64 + PqSignerInterface::MLDSA44_SIG_BYTES, strlen($raw));

        $res = $server->verify($headers, $body, 'POST', '/hq', '');
        $this->assertTrue($res['ok'], $res['error'] ?? '');
        $this->assertSame(['pq' => true], $res['json']);
    }

    public function testHybridResponseRoundTrip(): void
    {
        $clientKp = sodium_crypto_sign_keypair();
        $serverKp = sodium_crypto_sign_keypair();
        $clientSk = sodium_crypto_sign_secretkey($clientKp);
        $clientPk = sodium_crypto_sign_publickey($clientKp);
        $serverSk = sodium_crypto_sign_secretkey($serverKp);
        $serverPk = sodium_crypto_sign_publickey($serverKp);
        $mldsaClient = str_repeat("\x22", PqSignerInterface::MLDSA44_PUBLIC_BYTES);
        $mldsaServer = str_repeat("\x33", PqSignerInterface::MLDSA44_PUBLIC_BYTES);
        $signer = new FakeMldsa44Signer();
        $clock = static fn (): int => 1_700_000_000;

        $client = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => SecurePayload::SIGN_ALG_HYBRID,
            'version' => '4',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'ed25519SecretKeyB64' => base64_encode($clientSk),
            'ed25519PublicKeyServerB64' => base64_encode($serverPk),
            'mldsaPublicKeyB64' => base64_encode($mldsaClient),
            'mldsaPublicKeyServerB64' => base64_encode($mldsaServer),
            'pqSigner' => $signer,
            'clock' => $clock,
            'nonceGenerator' => static fn (): string => base64_encode(str_repeat("\x0d", 16)),
        ]);
        $server = new SecurePayload([
            'mode' => 'hmac',
            'signAlg' => SecurePayload::SIGN_ALG_HYBRID,
            'version' => '4',
            'ed25519SecretKeyServerB64' => base64_encode($serverSk),
            'mldsaPublicKeyB64' => base64_encode($mldsaClient),
            'mldsaPublicKeyServerB64' => base64_encode($mldsaServer),
            'pqSigner' => $signer,
            'clock' => $clock,
            'respNonceGenerator' => static fn (): string => base64_encode(str_repeat("\x0e", 16)),
            'replayStore' => static fn (string $k, int $t): bool => true,
            'keyLoader' => static function () use ($clientPk, $mldsaClient, $serverSk): array {
                return [
                    'hmacSecret' => null,
                    'aeadKeyB64' => null,
                    'ed25519PublicKeyB64' => base64_encode($clientPk),
                    'ed25519SecretKeyServerB64' => base64_encode($serverSk),
                    'mldsaPublicKeyB64' => base64_encode($mldsaClient),
                ];
            },
        ]);

        [$reqH, $reqB] = $client->buildHeadersAndBody('https://api.test/r', 'POST', ['a' => 1]);
        $v = $server->verify($reqH, $reqB, 'POST', '/r', '');
        $this->assertTrue($v['ok']);

        [$respH, $respB] = $server->buildResponse($reqH, ['ok' => true]);
        $this->assertSame(SecurePayload::HYBRID_ALG, $respH[SecurePayload::HX_RESP_SIG_ALG]);

        $vr = $client->verifyResponse($respH, $respB, $reqH[SecurePayload::HX_NONCE]);
        $this->assertTrue($vr['ok'], $vr['error'] ?? '');
        $this->assertSame(['ok' => true], $vr['json']);
    }
}
