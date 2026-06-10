<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Security;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

/**
 * Regresi keamanan untuk dua kerentanan yang ditemukan saat audit:
 *
 *  F1 — Downgrade enkripsi pada mode 'both':
 *       server bermode 'both' tidak boleh menerima request tanpa header AEAD
 *       (mencegah penurunan diam-diam menjadi HMAC-only / plaintext).
 *
 *  F2 — Replay pada mode 'aead' via mutasi timestamp:
 *       kunci replay tidak boleh menyertakan timestamp, sehingga sebuah nonce
 *       wajib sekali-pakai meskipun penyerang mengubah header timestamp yang
 *       (pada mode 'aead') tidak terotentikasi.
 *
 * Tes-tes ini GAGAL pada implementasi sebelum perbaikan dan LULUS sesudahnya.
 */
final class DowngradeAndReplayTest extends TestCase
{
    private const HMAC_32 = 'test-hmac-secret-must-be-32bytes!!';

    private function aeadKeyB64(): string
    {
        // Kunci AEAD 32-byte deterministik untuk reproducibility.
        return base64_encode(str_repeat("\x11", 32));
    }

    /** Server 'both' dengan kedua kunci tersedia. */
    private function makeBothServer(?callable $replayStore = null): SecurePayload
    {
        $opts = [
            'mode' => 'both',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => $this->aeadKeyB64()],
        ];
        if ($replayStore) {
            $opts['replayStore'] = $replayStore;
        }
        return new SecurePayload($opts);
    }

    /** Server 'aead' (hanya enkripsi). */
    private function makeAeadServer(?callable $replayStore = null): SecurePayload
    {
        $opts = [
            'mode' => 'aead',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => null, 'aeadKeyB64' => $this->aeadKeyB64()],
        ];
        if ($replayStore) {
            $opts['replayStore'] = $replayStore;
        }
        return new SecurePayload($opts);
    }

    // ---------------------------------------------------------------------
    // F1 — Encryption downgrade
    // ---------------------------------------------------------------------

    public function testBothModeRejectsRequestWithoutAeadHeaders(): void
    {
        // Penyerang (memiliki HMAC secret) membuat request HMAC-only + body plaintext.
        $attacker = new SecurePayload([
            'mode' => 'hmac',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::HMAC_32,
        ]);
        [$headers, $body] = $attacker->buildHeadersAndBody('https://api/v1/transfer', 'POST', ['amount' => 9999]);

        // Tidak ada satupun header AEAD yang terkirim.
        $this->assertArrayNotHasKey('X-AEAD-Algorithm', $headers);

        $server = $this->makeBothServer();
        $res = $server->verify($headers, $body, 'POST', '/v1/transfer', []);

        $this->assertFalse($res['ok'], 'Server "both" menerima request tanpa enkripsi (downgrade!).');
        $this->assertSame(401, $res['status']);
        $this->assertStringContainsString('mewajibkan enkripsi AEAD', $res['error']);
    }

    public function testAeadModeRejectsRequestWithoutAeadHeaders(): void
    {
        $attacker = new SecurePayload([
            'mode' => 'hmac',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::HMAC_32,
        ]);
        [$headers, $body] = $attacker->buildHeadersAndBody('https://api/v1/x', 'POST', ['a' => 1]);

        $server = $this->makeAeadServer();
        $res = $server->verify($headers, $body, 'POST', '/v1/x', []);

        $this->assertFalse($res['ok']);
        $this->assertSame(401, $res['status']);
        $this->assertStringContainsString('mewajibkan enkripsi AEAD', $res['error']);
    }

    public function testBothModeRoundTripStillSucceeds(): void
    {
        // Sanity: perbaikan tidak merusak alur sah mode 'both'.
        $client = new SecurePayload([
            'mode' => 'both',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::HMAC_32,
            'aeadKeyB64' => $this->aeadKeyB64(),
        ]);
        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/ok', 'POST', ['hello' => 'world']);

        $res = $this->makeBothServer()->verify($headers, $body, 'POST', '/v1/ok', []);

        $this->assertTrue($res['ok'], $res['error'] ?? '');
        $this->assertSame('BOTH', $res['mode']);
        $this->assertSame('world', $res['json']['hello']);
    }

    public function testBothModeWithAeadButMissingSignatureIsRejected(): void
    {
        // Lawan dari F1: AEAD ada tapi HMAC dihapus -> tetap ditolak.
        $client = new SecurePayload([
            'mode' => 'both',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::HMAC_32,
            'aeadKeyB64' => $this->aeadKeyB64(),
        ]);
        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/ok', 'POST', ['x' => 1]);
        unset($headers['X-Signature'], $headers['X-Signature-Algorithm']);

        $res = $this->makeBothServer()->verify($headers, $body, 'POST', '/v1/ok', []);
        $this->assertFalse($res['ok']);
    }

    // ---------------------------------------------------------------------
    // F2 — Replay via timestamp mutation
    // ---------------------------------------------------------------------

    public function testAeadReplayWithMutatedTimestampIsBlocked_FileStore(): void
    {
        $client = new SecurePayload([
            'mode' => 'aead',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'aeadKeyB64' => $this->aeadKeyB64(),
        ]);
        [$headers, $body] = $client->buildHeadersAndBody('https://api/x/y', 'POST', ['msg' => 'transfer']);

        $server = $this->makeAeadServer();

        $r1 = $server->verify($headers, $body, 'POST', '/x/y', []);
        $this->assertTrue($r1['ok'], $r1['error'] ?? '');

        // Replay: nonce sama, hanya timestamp dinaikkan (tidak terotentikasi di mode aead).
        $mutated = $headers;
        $mutated['X-Timestamp'] = (string) ((int) $headers['X-Timestamp'] + 1);

        $r2 = $server->verify($mutated, $body, 'POST', '/x/y', []);
        $this->assertFalse($r2['ok'], 'Replay dengan timestamp dimutasi seharusnya diblokir.');
        $this->assertStringContainsString('Replay detected', $r2['error']);
    }

    public function testReplayKeyDoesNotDependOnTimestamp_CustomStore(): void
    {
        // Bukti deterministik bahwa kunci replay tidak menyertakan timestamp:
        // dua request dengan nonce sama namun timestamp berbeda harus menghasilkan
        // cacheKey yang IDENTIK saat diserahkan ke replayStore kustom.
        $seenKeys = [];
        $store = function (string $key, int $ttl) use (&$seenKeys): bool {
            $seenKeys[] = $key;
            return true; // selalu anggap baru; kita hanya memeriksa key-nya.
        };

        $client = new SecurePayload([
            'mode' => 'aead',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'aeadKeyB64' => $this->aeadKeyB64(),
        ]);
        [$headers, $body] = $client->buildHeadersAndBody('https://api/x/y', 'POST', ['m' => 1]);

        $server = $this->makeAeadServer($store);

        $server->verify($headers, $body, 'POST', '/x/y', []);

        $mutated = $headers;
        $mutated['X-Timestamp'] = (string) ((int) $headers['X-Timestamp'] + 5);
        $server->verify($mutated, $body, 'POST', '/x/y', []);

        $this->assertCount(2, $seenKeys);
        $this->assertSame($seenKeys[0], $seenKeys[1], 'Kunci replay berubah saat timestamp berubah (F2 belum tertutup).');
    }

    public function testCustomStoreReceivesMemoryTtlCoveringFullWindow(): void
    {
        // TTL yang diberikan ke store harus mencakup replayTtl + clockSkew,
        // bukan hanya replayTtl, agar nonce diingat selama timestamp masih bisa lolos.
        $captured = null;
        $store = function (string $key, int $ttl) use (&$captured): bool {
            $captured = $ttl;
            return true;
        };

        $client = new SecurePayload([
            'mode' => 'aead',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'aeadKeyB64' => $this->aeadKeyB64(),
        ]);
        [$headers, $body] = $client->buildHeadersAndBody('https://api/x/y', 'POST', ['m' => 1]);

        // replayTtl=120 (default), clockSkew=30 -> memoryTtl harus 150.
        $server = new SecurePayload([
            'mode' => 'aead',
            'clockSkew' => 30,
            'replayStore' => $store,
            'keyLoader' => fn($c, $k) => ['hmacSecret' => null, 'aeadKeyB64' => $this->aeadKeyB64()],
        ]);
        $server->verify($headers, $body, 'POST', '/x/y', []);

        $this->assertSame(150, $captured);
    }
}
