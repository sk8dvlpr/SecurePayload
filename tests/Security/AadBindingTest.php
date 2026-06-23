<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Security;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

/**
 * Regresi keamanan untuk Phase 3 — pengikatan timestamp & header kritikal ke AAD.
 *
 * Invarian yang diuji:
 *  - timestamp request (X-Timestamp) terikat ke AAD: manipulasinya menggagalkan
 *    dekripsi, walau nilainya masih dalam jendela kesegaran (mode 'aead' yang
 *    tidak ditandatangani HMAC),
 *  - header kritikal yang dipilih lewat `bindHeaders` terikat ke AAD: perubahan
 *    maupun penghapusan nilainya menggagalkan dekripsi,
 *  - konfigurasi `bindHeaders` yang berbeda antara client & server menggagalkan
 *    dekripsi (AAD harus identik di kedua sisi),
 *  - timestamp response (X-Resp-Timestamp) terikat ke AAD response.
 */
final class AadBindingTest extends TestCase
{
    private const HMAC_32 = 'test-hmac-secret-must-be-32bytes!!';

    private function aeadKeyB64(): string
    {
        return base64_encode(str_repeat("\x11", 32));
    }

    /**
     * @param array<string,mixed> $extra
     */
    private function makeClient(string $mode, array $extra = []): SecurePayload
    {
        return new SecurePayload(array_merge([
            'mode' => $mode,
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::HMAC_32,
            'aeadKeyB64' => $this->aeadKeyB64(),
        ], $extra));
    }

    /**
     * @param array<string,mixed> $extra
     */
    private function makeServer(string $mode, array $extra = []): SecurePayload
    {
        return new SecurePayload(array_merge([
            'mode' => $mode,
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => $this->aeadKeyB64()],
        ], $extra));
    }

    public function testTamperedTimestampFailsAeadDecryption(): void
    {
        $client = $this->makeClient('aead');
        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['ping' => 1]);

        // Geser timestamp ke nilai LAIN yang masih dalam jendela kesegaran,
        // sehingga yang teruji adalah binding AAD, bukan validasi kesegaran.
        $newTs = (string) ((int) $headers[SecurePayload::HX_TIMESTAMP] - 5);
        $headers[SecurePayload::HX_TIMESTAMP] = $newTs;

        $res = $this->makeServer('aead')->verify($headers, $body, 'POST', '/v1/x', []);
        $this->assertFalse($res['ok'], 'Timestamp yang diubah seharusnya menggagalkan dekripsi.');
        $this->assertStringContainsString('mendekripsi', $res['error']);
    }

    public function testTamperedTimestampFailsBothModeDecryption(): void
    {
        $client = $this->makeClient('both');
        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['ping' => 1]);

        $newTs = (string) ((int) $headers[SecurePayload::HX_TIMESTAMP] - 5);
        $headers[SecurePayload::HX_TIMESTAMP] = $newTs;

        // Dekripsi (AEAD) dievaluasi sebelum HMAC, jadi kegagalan AAD muncul lebih dulu.
        $res = $this->makeServer('both')->verify($headers, $body, 'POST', '/v1/x', []);
        $this->assertFalse($res['ok'], 'Timestamp yang diubah seharusnya menggagalkan dekripsi pada mode both.');
        $this->assertStringContainsString('mendekripsi', $res['error']);
    }

    public function testBoundHeaderRoundTripSucceeds(): void
    {
        $bind = ['bindHeaders' => ['X-Request-Id']];
        $client = $this->makeClient('aead', $bind);
        $server = $this->makeServer('aead', $bind);

        [$headers, $body] = $client->buildHeadersAndBody(
            'https://api/v1/x',
            'POST',
            ['ping' => 1],
            ['X-Request-Id' => 'req-abc-123']
        );
        // Nilai header ikut terkirim agar server bisa membaca nilai yang sama.
        $this->assertSame('req-abc-123', $headers['X-Request-Id']);

        $res = $server->verify($headers, $body, 'POST', '/v1/x', []);
        $this->assertTrue($res['ok'], 'Header terikat yang konsisten seharusnya lolos verifikasi.');
        $this->assertSame(['ping' => 1], $res['json']);
    }

    public function testTamperedBoundHeaderFailsDecryption(): void
    {
        $bind = ['bindHeaders' => ['X-Request-Id']];
        $client = $this->makeClient('aead', $bind);
        $server = $this->makeServer('aead', $bind);

        [$headers, $body] = $client->buildHeadersAndBody(
            'https://api/v1/x',
            'POST',
            ['ping' => 1],
            ['X-Request-Id' => 'req-abc-123']
        );

        // Penyerang mengganti nilai header yang terikat.
        $headers['X-Request-Id'] = 'req-evil-999';

        $res = $server->verify($headers, $body, 'POST', '/v1/x', []);
        $this->assertFalse($res['ok'], 'Header terikat yang diubah seharusnya menggagalkan dekripsi.');
        $this->assertStringContainsString('mendekripsi', $res['error']);
    }

    public function testRemovedBoundHeaderFailsDecryption(): void
    {
        $bind = ['bindHeaders' => ['X-Request-Id']];
        $client = $this->makeClient('aead', $bind);
        $server = $this->makeServer('aead', $bind);

        [$headers, $body] = $client->buildHeadersAndBody(
            'https://api/v1/x',
            'POST',
            ['ping' => 1],
            ['X-Request-Id' => 'req-abc-123']
        );

        // Penyerang menghapus header terikat; server memperlakukannya sebagai
        // string kosong sehingga AAD berbeda dan dekripsi gagal.
        unset($headers['X-Request-Id']);

        $res = $server->verify($headers, $body, 'POST', '/v1/x', []);
        $this->assertFalse($res['ok'], 'Penghapusan header terikat seharusnya menggagalkan dekripsi.');
        $this->assertStringContainsString('mendekripsi', $res['error']);
    }

    public function testMismatchedBindConfigFailsDecryption(): void
    {
        // Client mengikat header, server tidak — AAD tidak identik, dekripsi gagal.
        $client = $this->makeClient('aead', ['bindHeaders' => ['X-Request-Id']]);
        $server = $this->makeServer('aead'); // tanpa bindHeaders

        [$headers, $body] = $client->buildHeadersAndBody(
            'https://api/v1/x',
            'POST',
            ['ping' => 1],
            ['X-Request-Id' => 'req-abc-123']
        );

        $res = $server->verify($headers, $body, 'POST', '/v1/x', []);
        $this->assertFalse($res['ok'], 'Konfigurasi bindHeaders yang berbeda seharusnya menggagalkan dekripsi.');
        $this->assertStringContainsString('mendekripsi', $res['error']);
    }

    public function testBoundHeaderIsCaseInsensitive(): void
    {
        $bind = ['bindHeaders' => ['X-Request-Id']];
        $client = $this->makeClient('aead', $bind);
        $server = $this->makeServer('aead', $bind);

        [$headers, $body] = $client->buildHeadersAndBody(
            'https://api/v1/x',
            'POST',
            ['ping' => 1],
            ['X-Request-Id' => 'req-abc-123']
        );

        // Server menerima header dengan kapitalisasi berbeda (umum pada HTTP stack).
        $value = $headers['X-Request-Id'];
        unset($headers['X-Request-Id']);
        $headers['x-request-id'] = $value;

        $res = $server->verify($headers, $body, 'POST', '/v1/x', []);
        $this->assertTrue($res['ok'], 'Binding header harus toleran terhadap perbedaan kapitalisasi.');
    }

    public function testTamperedResponseTimestampFailsDecryption(): void
    {
        $client = $this->makeClient('aead');
        [$reqHeaders] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['ping' => 1]);

        $server = $this->makeServer('aead');
        [$respHeaders, $respBody] = $server->buildResponse($reqHeaders, ['amount' => 100]);

        // Geser timestamp response ke nilai lain yang masih segar.
        $newTs = (string) ((int) $respHeaders[SecurePayload::HX_RESP_TIMESTAMP] - 5);
        $respHeaders[SecurePayload::HX_RESP_TIMESTAMP] = $newTs;

        $res = $client->verifyResponse($respHeaders, $respBody, $reqHeaders[SecurePayload::HX_NONCE]);
        $this->assertFalse($res['ok'], 'Timestamp response yang diubah seharusnya menggagalkan dekripsi.');
        $this->assertStringContainsString('mendekripsi', $res['error']);
    }
}
