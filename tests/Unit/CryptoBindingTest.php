<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

/**
 * Melengkapi cakupan tes untuk properti binding kriptografis dan helper statis
 * yang belum diuji eksplisit: pengikatan method/path ke nonce AEAD, determinisme
 * hmacMessage, kebenaran digest, serta cabang validasi integritas file.
 */
final class CryptoBindingTest extends TestCase
{
    private const HMAC_32 = 'test-hmac-secret-must-be-32bytes!!';

    private function aeadKeyB64(): string
    {
        return base64_encode(str_repeat("\x22", 32));
    }

    private function aeadClient(): SecurePayload
    {
        return new SecurePayload([
            'mode' => 'aead',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'aeadKeyB64' => $this->aeadKeyB64(),
        ]);
    }

    private function aeadServer(): SecurePayload
    {
        return new SecurePayload([
            'mode' => 'aead',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => null, 'aeadKeyB64' => $this->aeadKeyB64()],
        ]);
    }

    // --- AEAD request-binding (nonce mengikat method/path/query) ---

    public function testAeadMethodTamperIsRejected(): void
    {
        [$h, $b] = $this->aeadClient()->buildHeadersAndBody('https://api/x/y', 'POST', ['a' => 1]);
        // Kirim ke method berbeda; nonce yang dihitung server tak akan cocok.
        $res = $this->aeadServer()->verify($h, $b, 'GET', '/x/y', []);
        $this->assertFalse($res['ok']);
        $this->assertSame(401, $res['status']);
    }

    public function testAeadPathTamperIsRejected(): void
    {
        [$h, $b] = $this->aeadClient()->buildHeadersAndBody('https://api/x/y', 'POST', ['a' => 1]);
        $res = $this->aeadServer()->verify($h, $b, 'POST', '/x/DIFFERENT', []);
        $this->assertFalse($res['ok']);
        $this->assertSame(401, $res['status']);
    }

    public function testAeadQueryTamperIsRejected(): void
    {
        [$h, $b] = $this->aeadClient()->buildHeadersAndBody('https://api/x/y?a=1', 'POST', ['a' => 1]);
        $res = $this->aeadServer()->verify($h, $b, 'POST', '/x/y', ['a' => '2']);
        $this->assertFalse($res['ok']);
        $this->assertSame(401, $res['status']);
    }

    public function testAeadUnicodePayloadRoundTrip(): void
    {
        $payload = ['nama' => 'Budi 日本語 🚀', 'nilai' => 'çà&é"'];
        [$h, $b] = $this->aeadClient()->buildHeadersAndBody('https://api/u', 'POST', $payload);
        $res = $this->aeadServer()->verify($h, $b, 'POST', '/u', []);
        $this->assertTrue($res['ok'], $res['error'] ?? '');
        $this->assertSame($payload, $res['json']);
    }

    // --- Static helper correctness ---

    public function testBodyDigestB64MatchesSha256(): void
    {
        $body = '{"a":1}';
        $this->assertSame(
            base64_encode(hash('sha256', $body, true)),
            SecurePayload::bodyDigestB64($body)
        );
    }

    public function testGenNonceB64Decodes16RandomBytes(): void
    {
        $n1 = SecurePayload::genNonceB64();
        $n2 = SecurePayload::genNonceB64();
        $this->assertSame(16, strlen(base64_decode($n1, true)));
        $this->assertNotSame($n1, $n2, 'Nonce harus acak/unik antar pemanggilan.');
    }

    public function testAeadNonceFromBindsContextAndHasCorrectLength(): void
    {
        $seed = SecurePayload::genNonceB64();
        $a = SecurePayload::aeadNonceFrom($seed, 'POST', '/x', 'q=1');
        $b = SecurePayload::aeadNonceFrom($seed, 'GET', '/x', 'q=1');   // method beda
        $c = SecurePayload::aeadNonceFrom($seed, 'POST', '/y', 'q=1');  // path beda

        $expectedLen = defined('SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES')
            ? SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES : 24;
        $this->assertSame($expectedLen, strlen($a));
        $this->assertNotSame($a, $b);
        $this->assertNotSame($a, $c);
    }

    public function testHmacMessageIsDeterministicAndFieldSensitive(): void
    {
        $args = ['1', 'c1', 'k1', '1700000000', 'nonceB64', 'POST', '/x', 'q=1', 'digestB64'];
        $m1 = SecurePayload::hmacMessage(...$args);
        $m2 = SecurePayload::hmacMessage(...$args);
        $this->assertSame($m1, $m2);

        $changed = $args;
        $changed[5] = 'GET'; // ubah method
        $this->assertNotSame($m1, SecurePayload::hmacMessage(...$changed));
    }

    // --- verifyFilePayload integrity branches ---

    /** Klien HMAC yang menandatangani payload mentah apa adanya. */
    private function signRawPayload(array $payload): array
    {
        $client = new SecurePayload([
            'mode' => 'hmac',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::HMAC_32,
        ]);
        return $client->buildHeadersAndBody('https://api/upload', 'POST', $payload);
    }

    private function hmacFileServer(): SecurePayload
    {
        return new SecurePayload([
            'mode' => 'hmac',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null],
        ]);
    }

    public function testVerifyFilePayloadRejectsSizeIntegrityMismatch(): void
    {
        // Payload tertandatangani sah, tetapi 'size' tidak cocok dengan konten asli.
        [$h, $b] = $this->signRawPayload([
            '_attachment' => [
                'name' => 'a.txt',
                'size' => 999,                       // bohong
                'type' => 'text/plain',
                'content' => base64_encode('hi'),    // sebenarnya 2 byte
            ],
        ]);
        $res = $this->hmacFileServer()->verifyFilePayload($h, $b, 'POST', '/upload');
        $this->assertFalse($res['ok']);
        $this->assertStringContainsString('Integritas ukuran file', $res['error']);
    }

    public function testVerifyFilePayloadRejectsInvalidBase64Content(): void
    {
        [$h, $b] = $this->signRawPayload([
            '_attachment' => [
                'name' => 'a.txt',
                'size' => 2,
                'type' => 'text/plain',
                'content' => '@@not-base64@@',
            ],
        ]);
        $res = $this->hmacFileServer()->verifyFilePayload($h, $b, 'POST', '/upload');
        $this->assertFalse($res['ok']);
        $this->assertStringContainsString('decode konten file', $res['error']);
    }

    public function testVerifyFilePayloadAllowedExtsRejectsDisallowed(): void
    {
        [$h, $b] = $this->signRawPayload([
            '_attachment' => [
                'name' => 'note.txt',
                'size' => 2,
                'type' => 'text/plain',
                'content' => base64_encode('hi'),
            ],
        ]);
        // Whitelist hanya pdf -> .txt ditolak.
        $res = $this->hmacFileServer()->verifyFilePayload($h, $b, 'POST', '/upload', ['allowed_exts' => ['pdf']]);
        $this->assertFalse($res['ok']);
        $this->assertSame(422, $res['status']);
        $this->assertStringContainsString('tidak diizinkan', $res['error']);
    }
}
