<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Integration;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

/**
 * Integrasi round-trip kompresi payload.
 *
 * Mencakup:
 *  - client `compress:true` mode hmac|aead|both → server verifyOrThrow()['json'] benar,
 *  - header X-Payload-Encoding eksplisit ('gzip'/'br', atau 'identity' untuk body kecil),
 *  - REGRESI: client compress:false kompatibel dua arah dengan server tanpa fitur ini
 *    (wire tidak berubah, header encoding TIDAK dikirim),
 *  - header X-Payload-Encoding dipalsukan ('zstd') → ok:false status 400 (fail-closed).
 */
final class CompressedRoundTripTest extends TestCase
{
    private const HMAC_32 = 'test-hmac-secret-must-be-32bytes!!';

    private function aeadKeyB64(): string
    {
        return base64_encode(str_repeat("\x33", 32));
    }

    private function client(string $mode, bool $compress): SecurePayload
    {
        return new SecurePayload([
            'mode' => $mode,
            'compress' => $compress,
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::HMAC_32,
            'aeadKeyB64' => $this->aeadKeyB64(),
        ]);
    }

    /** Server dengan opsi dekompresi saja - tanpa opsi client lain. */
    private function server(string $mode): SecurePayload
    {
        return new SecurePayload([
            'mode' => $mode,
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

    /** @return array<string,mixed> Payload besar & compressible (> MIN_SIZE). */
    private function bigPayload(): array
    {
        return [
            'deskripsi' => str_repeat('data berulang yang sangat mudah dikompresi ', 120),
            'flag' => true,
        ];
    }

    /**
     * @dataProvider modes
     */
    public function testCompressedRoundTrip(string $mode): void
    {
        $this->skipIfNoSodium($mode);

        $client = $this->client($mode, true);
        $server = $this->server($mode);
        $payload = $this->bigPayload();

        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/data?b=2&a=1', 'POST', $payload);

        // Header encoding eksplisit dan bernilai algoritma terkompresi.
        $this->assertArrayHasKey(SecurePayload::HX_PAYLOAD_ENCODING, $headers);
        $this->assertContains($headers[SecurePayload::HX_PAYLOAD_ENCODING], ['gzip', 'br']);
        $this->assertLessThan(
            strlen(json_encode($payload) ?: ''),
            strlen($body),
            "Mode $mode: byte terkirim harus lebih kecil dari JSON asli."
        );

        $res = $server->verifyOrThrow($headers, $body, 'POST', '/v1/data', 'b=2&a=1');
        $this->assertSame($payload, $res['json'], "Mode $mode: isi setelah dekompresi harus identik dengan payload asli.");
        $this->assertSame(json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), $res['bodyPlain']);
    }

    /**
     * @dataProvider modes
     */
    public function testCompressAktifBodyKecilIdentityEksplisit(string $mode): void
    {
        $this->skipIfNoSodium($mode);

        $client = $this->client($mode, true);
        $server = $this->server($mode);

        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/kecil', 'POST', ['n' => 1]);
        $this->assertSame('identity', $headers[SecurePayload::HX_PAYLOAD_ENCODING], "Mode $mode: body kecil wajib dilabel identity eksplisit.");

        $res = $server->verifyOrThrow($headers, $body, 'POST', '/v1/kecil', []);
        $this->assertSame(['n' => 1], $res['json']);
    }

    /**
     * Regresi inti : tanpa opsi compress, wire IDENTIK — header
     * encoding tidak pernah muncul, dan server lama (tanpa fitur kompresi) tetap
     * menerima request; sebaliknya server baru juga menerima client lama.
     *
     * @dataProvider modes
     */
    public function testRegresiTanpaFiturKompatibelDuaArah(string $mode): void
    {
        $this->skipIfNoSodium($mode);

        // Client compress:false (default) → perilaku existing.
        $clientLama = new SecurePayload([
            'mode' => $mode,
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::HMAC_32,
            'aeadKeyB64' => $this->aeadKeyB64(),
        ]);
        $payload = ['hello' => 'dunia'];

        [$headers, $body] = $clientLama->buildHeadersAndBody('https://api/v1/x', 'POST', $payload);
        $this->assertArrayNotHasKey(SecurePayload::HX_PAYLOAD_ENCODING, $headers, 'Tanpa compress, header encoding TIDAK boleh dikirim.');

        // Server tanpa opsi kompresi apa pun (simulasi deployment lawan yang belum upgrade).
        $serverLama = new SecurePayload([
            'mode' => $mode,
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => $this->aeadKeyB64()],
        ]);
        $res = $serverLama->verifyOrThrow($headers, $body, 'POST', '/v1/x', []);
        $this->assertSame($payload, $res['json']);

        // Server berkemampuan dekompresi menerima client lama secara identik.
        // Request dibangun ulang (nonce segar) agar tidak tertangkap anti-replay
        // karena memakai request yang sama persis dua kali.
        [$headers2, $body2] = $clientLama->buildHeadersAndBody('https://api/v1/x', 'POST', $payload);
        $resBaru = $this->server($mode)->verifyOrThrow($headers2, $body2, 'POST', '/v1/x', []);
        $this->assertSame($payload, $resBaru['json']);
    }

    /**
     * Header encoding dipalsukan (tidak terikat signature/AAD by default):
     * integritas tetap lolos karena byte asli, namun nilai 'zstd' tak dikenal
     * HARUS menolak fail-closed dengan status 400.
     *
     * @dataProvider modes
     */
    public function testHeaderEncodingAsingDipalsukanDitolak400(string $mode): void
    {
        $this->skipIfNoSodium($mode);

        $client = $this->client($mode, false); // request sah tanpa kompresi
        $server = $this->server($mode);

        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['n' => 7]);
        $headers['X-Payload-Encoding'] = 'zstd'; // injeksi attacker

        $res = $server->verify($headers, $body, 'POST', '/v1/x', []);
        $this->assertFalse($res['ok'], "Mode $mode: encoding palsu harus ditolak.");
        $this->assertSame(400, $res['status']);
    }
}
