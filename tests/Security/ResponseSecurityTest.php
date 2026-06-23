<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Security;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

/**
 * Regresi keamanan untuk pengamanan RESPONSE (Phase 2):
 *  - response yang di-tamper harus ditolak,
 *  - response tidak boleh bisa dipindah (relocation) ke konteks request lain
 *    (binding ke nonce request asal),
 *  - mode aead/both menolak response tanpa enkripsi (anti-downgrade),
 *  - timestamp response usang ditolak.
 */
final class ResponseSecurityTest extends TestCase
{
    private const HMAC_32 = 'test-hmac-secret-must-be-32bytes!!';

    private function aeadKeyB64(): string
    {
        return base64_encode(str_repeat("\x11", 32));
    }

    private function makeClient(string $mode): SecurePayload
    {
        return new SecurePayload([
            'mode' => $mode,
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::HMAC_32,
            'aeadKeyB64' => $this->aeadKeyB64(),
        ]);
    }

    private function makeServer(string $mode): SecurePayload
    {
        return new SecurePayload([
            'mode' => $mode,
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => $this->aeadKeyB64()],
        ]);
    }

    public function testTamperedHmacResponseBodyRejected(): void
    {
        $client = $this->makeClient('hmac');
        [$reqHeaders] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['ping' => 1]);

        [$respHeaders, $respBody] = $this->makeServer('hmac')->buildResponse($reqHeaders, ['amount' => 100]);

        // Penyerang mengubah body response.
        $tampered = json_encode(['amount' => 999999]);

        $res = $client->verifyResponse($respHeaders, $tampered, $reqHeaders[SecurePayload::HX_NONCE]);
        $this->assertFalse($res['ok'], 'Response body yang diubah seharusnya ditolak.');
    }

    public function testResponseRelocationToDifferentRequestRejected(): void
    {
        $client = $this->makeClient('hmac');
        $server = $this->makeServer('hmac');

        // Dua request berbeda menghasilkan nonce berbeda.
        [$reqA] = $client->buildHeadersAndBody('https://api/v1/a', 'POST', ['a' => 1]);
        [$reqB] = $client->buildHeadersAndBody('https://api/v1/b', 'POST', ['b' => 2]);
        $this->assertNotSame($reqA[SecurePayload::HX_NONCE], $reqB[SecurePayload::HX_NONCE]);

        // Server membuat response untuk request A.
        [$respHeaders, $respBody] = $server->buildResponse($reqA, ['for' => 'A']);

        // Penyerang mencoba memakai response A sebagai jawaban request B.
        $res = $client->verifyResponse($respHeaders, $respBody, $reqB[SecurePayload::HX_NONCE]);
        $this->assertFalse($res['ok'], 'Response tidak boleh valid untuk nonce request lain (relocation).');

        // Sanity: untuk request asalnya, tetap valid.
        $ok = $client->verifyResponse($respHeaders, $respBody, $reqA[SecurePayload::HX_NONCE]);
        $this->assertTrue($ok['ok'], $ok['error'] ?? '');
    }

    public function testAeadResponseRelocationRejected(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium required');
        }
        $client = $this->makeClient('aead');
        $server = $this->makeServer('aead');

        [$reqA] = $client->buildHeadersAndBody('https://api/v1/a', 'POST', ['a' => 1]);
        [$reqB] = $client->buildHeadersAndBody('https://api/v1/b', 'POST', ['b' => 2]);

        [$respHeaders, $respBody] = $server->buildResponse($reqA, ['secret' => 'x']);

        // Nonce AEAD response terikat ke nonce request A; dekripsi untuk B harus gagal.
        $res = $client->verifyResponse($respHeaders, $respBody, $reqB[SecurePayload::HX_NONCE]);
        $this->assertFalse($res['ok']);
    }

    public function testBothModeRejectsResponseWithoutAeadHeaders(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium required');
        }
        $client = $this->makeClient('both');
        [$reqHeaders] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['ping' => 1]);

        [$respHeaders, $respBody] = $this->makeServer('both')->buildResponse($reqHeaders, ['data' => 1]);

        // Hapus header AEAD response untuk mensimulasikan downgrade.
        unset($respHeaders[SecurePayload::HX_RESP_AEAD_ALG], $respHeaders[SecurePayload::HX_RESP_AEAD_NONCE]);

        $res = $client->verifyResponse($respHeaders, $respBody, $reqHeaders[SecurePayload::HX_NONCE]);
        $this->assertFalse($res['ok']);
        $this->assertStringContainsString('mewajibkan enkripsi AEAD', $res['error']);
    }

    public function testStaleResponseTimestampRejected(): void
    {
        $client = $this->makeClient('hmac');
        [$reqHeaders] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['ping' => 1]);

        $server = new SecurePayload([
            'mode' => 'hmac',
            'clockSkew' => 30,
            'replayTtl' => 60,
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null],
        ]);
        [$respHeaders, $respBody] = $server->buildResponse($reqHeaders, ['ok' => 1]);

        // Geser timestamp response ke masa lampau melampaui (replayTtl + clockSkew),
        // lalu hitung ulang signature agar yang teruji adalah validasi timestamp.
        $oldTs = (string) (time() - 1000);
        $respHeaders[SecurePayload::HX_RESP_TIMESTAMP] = $oldTs;
        $digest = substr($respHeaders[SecurePayload::HX_RESP_BODY_DIGEST], 7);
        $msg = SecurePayload::respMessage(
            '2',
            $reqHeaders[SecurePayload::HX_NONCE],
            $oldTs,
            $respHeaders[SecurePayload::HX_RESP_NONCE],
            $digest
        );
        $respHeaders[SecurePayload::HX_RESP_SIGNATURE] = base64_encode(hash_hmac('sha256', $msg, self::HMAC_32, true));

        $clientTight = new SecurePayload([
            'mode' => 'hmac',
            'clockSkew' => 30,
            'replayTtl' => 60,
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::HMAC_32,
        ]);
        $res = $clientTight->verifyResponse($respHeaders, $respBody, $reqHeaders[SecurePayload::HX_NONCE]);
        $this->assertFalse($res['ok']);
        $this->assertStringContainsString('Timestamp response', $res['error']);
    }
}
