<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Security;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

/**
 * Regresi keamanan Phase 5 — derivasi subkey HKDF (`deriveKeys`).
 *
 * Konfigurasi `deriveKeys` WAJIB sama di kedua sisi. Bila tidak cocok, verifikasi
 * harus GAGAL TERTUTUP (fail-closed): subkey efektif berbeda sehingga tanda
 * tangan/dekripsi tidak valid — tidak boleh ada jalur downgrade diam-diam.
 */
final class HkdfMismatchTest extends TestCase
{
    private const HMAC_32 = 'test-hmac-secret-must-be-32bytes!!';

    private function aeadKeyB64(): string
    {
        return base64_encode(str_repeat("\x33", 32));
    }

    private function make(string $mode, bool $derive, bool $isClient): SecurePayload
    {
        $opts = ['mode' => $mode, 'deriveKeys' => $derive];
        if ($isClient) {
            $opts += [
                'clientId' => 'c1',
                'keyId' => 'k1',
                'hmacSecretRaw' => self::HMAC_32,
                'aeadKeyB64' => $this->aeadKeyB64(),
            ];
        } else {
            $opts['keyLoader'] = fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => $this->aeadKeyB64()];
        }
        return new SecurePayload($opts);
    }

    public function testHmacRequestMismatchRejected(): void
    {
        $client = $this->make('hmac', true, true);   // client menurunkan subkey
        $server = $this->make('hmac', false, false);  // server pakai kunci langsung

        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['n' => 1]);
        $res = $server->verify($headers, $body, 'POST', '/v1/x', []);

        $this->assertFalse($res['ok'], 'deriveKeys tidak cocok harus menolak (HMAC).');
        $this->assertStringContainsString('Tanda Tangan', $res['error']);
    }

    public function testAeadRequestMismatchRejected(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium tidak tersedia');
        }
        $client = $this->make('aead', true, true);
        $server = $this->make('aead', false, false);

        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['n' => 1]);
        $res = $server->verify($headers, $body, 'POST', '/v1/x', []);

        $this->assertFalse($res['ok'], 'deriveKeys tidak cocok harus menggagalkan dekripsi (AEAD).');
        $this->assertStringContainsString('mendekripsi', $res['error']);
    }

    public function testResponseMismatchRejected(): void
    {
        // Server menurunkan subkey, client tidak → verifikasi response gagal.
        $client = $this->make('hmac', false, true);
        $server = $this->make('hmac', true, false);

        [$reqHeaders] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['ping' => 1]);
        [$respHeaders, $respBody] = $server->buildResponse($reqHeaders, ['ok' => 1]);

        $res = $client->verifyResponse($respHeaders, $respBody, $reqHeaders[SecurePayload::HX_NONCE]);
        $this->assertFalse($res['ok'], 'deriveKeys response tidak cocok harus ditolak.');
        $this->assertStringContainsString('Tanda Tangan response', $res['error']);
    }
}
