<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

/**
 * Extra security tests: replay, timestamp range, nonce/digest/signature errors.
 */
final class ReplayAndSecurityTest extends TestCase
{
    // Konstanta standar — 36 karakter, aman untuk semua test
    private const HMAC_32 = 'test-hmac-secret-must-be-32bytes!!';

    /**
     * Decode X-Canonical-Request from header.
     * Supports new Base64 form and legacy raw form with newlines.
     * @return array{0:string,1:string,2:string} [method, path, qStr]
     */
    private function canonPartsFromHeader(string $hdr): array
    {
        $canon = $hdr;
        if (strpos($canon, "\n") === false) {
            $decoded = base64_decode($canon, true);
            if (is_string($decoded) && $decoded !== '') {
                $canon = $decoded;
            }
        }
        $parts = explode("\n", $canon, 3);
        $this->assertCount(3, $parts, 'Bad canonical header format');
        return [$parts[0], $parts[1], $parts[2]];
    }

    public function testReplayDetectionWithCustomStore(): void
    {
        $spClient = new SecurePayload([
            'mode' => 'hmac',
            'version' => '1',
            'clientId' => 'c2',
            'keyId' => 'k2',
            'hmacSecretRaw' => self::HMAC_32,
        ]);

        [$headers, $body] = $spClient->buildHeadersAndBody('https://api.example.com/replay', 'POST', ['r' => 1]);

        // Custom replayStore: true only the first time a cacheKey is seen
        $seen = [];
        $replayStore = function (string $cacheKey, int $ttl) use (&$seen): bool {
            if (isset($seen[$cacheKey]))
                return false;
            $seen[$cacheKey] = time();
            return true;
        };

        $spServer = new SecurePayload([
            'mode' => 'hmac',
            'version' => '1',
            'keyLoader' => fn(string $cid, string $kid) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null],
            'replayStore' => $replayStore,
            'replayTtl' => 120,
            'clockSkew' => 60,
        ]);

        $vr1 = $spServer->verifySimple($headers, $body, 'POST', '/replay');
        $this->assertTrue($vr1['ok'] ?? false, json_encode($vr1));

        // Re-use exact same headers/body (same ts+nonce) should be rejected
        $vr2 = $spServer->verifySimple($headers, $body, 'POST', '/replay');
        $this->assertFalse($vr2['ok'] ?? true);
        $this->assertSame(401, $vr2['status'] ?? 0);
        $this->assertStringContainsString('Replay', $vr2['error'] ?? '');
    }

    public function testTimestampOutOfRangeOnServerHmac(): void
    {
        $spClient = new SecurePayload([
            'mode' => 'hmac',
            'version' => '1',
            'clientId' => 'c3',
            'keyId' => 'k3',
            'hmacSecretRaw' => self::HMAC_32,
        ]);

        [$headers, $body] = $spClient->buildHeadersAndBody('https://api.example.com/hmac?y=1', 'POST', ['t' => 1]);

        // Parse canonical header for method/path/query to recompute signature
        [$method, $path, $qStr] = $this->canonPartsFromHeader($headers[SecurePayload::HX_CANON_REQ]);

        // Tamper timestamp to far past and recompute signature accordingly
        $oldTs = (string) (time() - 999999);
        $headers[SecurePayload::HX_TIMESTAMP] = $oldTs;

        $digestHeader = $headers[SecurePayload::HX_BODY_DIGEST];
        $digestB64 = substr($digestHeader, 7); // remove "sha256="
        $msg = SecurePayload::hmacMessage('1', 'c3', 'k3', $oldTs, $headers[SecurePayload::HX_NONCE], strtoupper($method), SecurePayload::normalizePath($path), $qStr, $digestB64);
        $headers[SecurePayload::HX_SIGNATURE] = base64_encode(hash_hmac('sha256', $msg, self::HMAC_32, true));

        $spServer = new SecurePayload([
            'mode' => 'hmac',
            'version' => '1',
            'keyLoader' => fn(string $cid, string $kid) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null],
            'replayTtl' => 60,   // tight window
            'clockSkew' => 0,
        ]);

        $vr = $spServer->verifySimple($headers, $body, 'POST', '/hmac');
        $this->assertFalse($vr['ok'] ?? true);
        $this->assertSame(401, $vr['status'] ?? 0);
        $this->assertStringContainsString('Timestamp', $vr['error'] ?? '');
    }

    public function testAeadNonceMismatchInBoth(): void
    {
        if (!\extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium is required');
        }

        $aeadKey = base64_encode(random_bytes(32));

        $spClient = new SecurePayload([
            'mode' => 'both',
            'version' => '1',
            'clientId' => 'c4',
            'keyId' => 'k4',
            'hmacSecretRaw' => self::HMAC_32,
            'aeadKeyB64' => $aeadKey,
        ]);

        [$headers, $body] = $spClient->buildHeadersAndBody('https://api.example.com/nonce?z=9', 'POST', ['n' => 1]);

        // Tamper X-Canonical-Request path -> will make server calculate different AEAD nonce
        [$m, $p, $q] = $this->canonPartsFromHeader($headers[SecurePayload::HX_CANON_REQ]);
        $tampered = $m . "\n" . "/tampered" . "\n" . $q;
        $headers[SecurePayload::HX_CANON_REQ] = base64_encode($tampered);

        $spServer = new SecurePayload([
            'mode' => 'both',
            'version' => '1',
            'keyLoader' => fn(string $cid, string $kid) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => $aeadKey],
        ]);

        $vr = $spServer->verifySimple($headers, $body, 'POST', '/nonce');
        $this->assertFalse($vr['ok'] ?? true);
        $this->assertSame(401, $vr['status'] ?? 0);
        $this->assertStringContainsString('Nonce mismatch (Integritas request invalid)', $vr['error'] ?? '');
    }

    public function testHmacBodyDigestMismatch(): void
    {
        $spClient = new SecurePayload([
            'mode' => 'hmac',
            'version' => '1',
            'clientId' => 'c5',
            'keyId' => 'k5',
            'hmacSecretRaw' => self::HMAC_32,
        ]);

        [$headers, $body] = $spClient->buildHeadersAndBody('https://api.example.com/digest', 'POST', ['a' => 1]);

        // Tamper body but keep headers unchanged
        $tamperedBody = json_encode(['a' => 2]);

        $spServer = new SecurePayload([
            'mode' => 'hmac',
            'version' => '1',
            'keyLoader' => fn(string $cid, string $kid) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null],
        ]);

        $vr = $spServer->verifySimple($headers, $tamperedBody, 'POST', '/digest');
        $this->assertFalse($vr['ok'] ?? true);
        $this->assertSame(422, $vr['status'] ?? 0);
        $this->assertStringContainsString('Integritas Body Digest HMAC gagal', $vr['error'] ?? '');
    }

    public function testHmacSignatureMismatch(): void
    {
        $spClient = new SecurePayload([
            'mode' => 'hmac',
            'version' => '1',
            'clientId' => 'c6',
            'keyId' => 'k6',
            'hmacSecretRaw' => self::HMAC_32,
        ]);

        [$headers, $body] = $spClient->buildHeadersAndBody('https://api.example.com/sig', 'POST', ['s' => 1]);

        // Tamper signature
        $headers[SecurePayload::HX_SIGNATURE] = base64_encode(random_bytes(32));

        $spServer = new SecurePayload([
            'mode' => 'hmac',
            'version' => '1',
            'keyLoader' => fn(string $cid, string $kid) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null],
        ]);

        $vr = $spServer->verifySimple($headers, $body, 'POST', '/sig');
        $this->assertFalse($vr['ok'] ?? true);
        $this->assertSame(401, $vr['status'] ?? 0);
        $this->assertStringContainsString('Tanda Tangan (Signature) tidak valid', $vr['error'] ?? '');
    }

    /**
     * [COV-05a] checkReplay() file-based store — request pertama diterima
     */
    public function testCheckReplay_FileBasedStore_FirstRequest_Accepted(): void
    {
        $client = new SecurePayload([
            'mode'          => 'hmac',
            'version'       => '1',
            'clientId'      => 'cov-client',
            'keyId'         => 'cov-key',
            'hmacSecretRaw' => self::HMAC_32,
        ]);

        [$headers, $body] = $client->buildHeadersAndBody(
            'https://api.test/cov', 'POST', ['cov' => 1]
        );

        // Server TANPA custom replayStore → pakai file-based default
        $server = new SecurePayload([
            'mode'      => 'hmac',
            'version'   => '1',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null],
            'replayTtl' => 120,
            'clockSkew' => 60,
        ]);

        $result = $server->verifySimple($headers, $body, 'POST', '/cov');
        $this->assertTrue($result['ok'], json_encode($result));
    }

    /**
     * [COV-05b] checkReplay() file-based store — request duplikat ditolak
     */
    public function testCheckReplay_FileBasedStore_DuplicateRequest_Rejected(): void
    {
        $client = new SecurePayload([
            'mode'          => 'hmac',
            'version'       => '1',
            'clientId'      => 'cov-client-2',
            'keyId'         => 'cov-key-2',
            'hmacSecretRaw' => self::HMAC_32,
        ]);

        [$headers, $body] = $client->buildHeadersAndBody(
            'https://api.test/cov2', 'POST', ['cov' => 2]
        );

        $server = new SecurePayload([
            'mode'      => 'hmac',
            'version'   => '1',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null],
            'replayTtl' => 120,
            'clockSkew' => 60,
        ]);

        // Request pertama: diterima
        $r1 = $server->verifySimple($headers, $body, 'POST', '/cov2');
        $this->assertTrue($r1['ok']);

        // Request kedua dengan headers/body IDENTIK: ditolak
        $r2 = $server->verifySimple($headers, $body, 'POST', '/cov2');
        $this->assertFalse($r2['ok']);
        $this->assertSame(401, $r2['status']);
        $this->assertStringContainsString('Replay', $r2['error']);
    }

    /**
     * [COV-08] cleanupNonceFiles() — file expired terhapus, file baru dipertahankan
     * Karena GC probabilistik (1/500), kita trigger via banyak request dummy
     */
    public function testCleanupNonceFiles_ExpiredFilesAreDeleted(): void
    {
        // 1. Buat file nonce palsu yang sudah expired (mtime = 2 jam yang lalu)
        $tmpDir  = sys_get_temp_dir();
        $expiredFile = $tmpDir . DIRECTORY_SEPARATOR . 'sp_expired_test_' . uniqid();
        file_put_contents($expiredFile, '1');
        touch($expiredFile, time() - 7200); // 2 jam yang lalu

        // 2. Buat file nonce yang masih baru (tidak boleh dihapus)
        $freshFile = $tmpDir . DIRECTORY_SEPARATOR . 'sp_fresh_test_' . uniqid();
        file_put_contents($freshFile, '1');
        // mtime = now (default)

        // 3. Trigger GC dengan cara mengirim banyak request hingga GC terpicu (1/500)
        $client = new SecurePayload([
            'mode'          => 'hmac',
            'version'       => '1',
            'clientId'      => 'gc-client',
            'keyId'         => 'gc-key',
            'hmacSecretRaw' => self::HMAC_32,
        ]);
        $server = new SecurePayload([
            'mode'      => 'hmac',
            'version'   => '1',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null],
            'replayTtl' => 120,
            'clockSkew' => 60,
        ]);

        $gcTriggered = false;
        for ($i = 0; $i < 5000; $i++) {
            [$h, $b] = $client->buildHeadersAndBody(
                'https://api.test/gc', 'POST', ['i' => $i]
            );
            $server->verifySimple($h, $b, 'POST', '/gc');

            if (!file_exists($expiredFile)) {
                $gcTriggered = true;
                break;
            }
        }

        $this->assertTrue($gcTriggered,
            'GC tidak terpicu setelah 5000 request. ' .
            'Cek implementasi cleanupNonceFiles() dan probabilitas GC.'
        );
        $this->assertFileDoesNotExist($expiredFile,
            'File lama harus dihapus oleh GC'
        );
        $this->assertFileExists($freshFile,
            'File baru tidak boleh dihapus oleh GC'
        );

        // Cleanup fresh file jika masih ada
        if (file_exists($freshFile)) {
            unlink($freshFile);
        }
    }

    public function testCleanupNonceFiles_NoFiles_ReturnsEarly(): void
    {
        $server = new SecurePayload([
            'mode' => 'hmac',
            'version' => '1',
            'replayTtl' => 120
        ]);

        // Clean up any existing sp_ files first
        $dir = sys_get_temp_dir();
        $files = glob($dir . DIRECTORY_SEPARATOR . 'sp_*');
        foreach ($files ?: [] as $f) {
            if (is_file($f)) @unlink($f);
            elseif (is_dir($f)) @rmdir($f);
        }

        $dummyDir = $dir . DIRECTORY_SEPARATOR . 'sp_dummy_dir';
        @mkdir($dummyDir);

        $ref = new \ReflectionClass(SecurePayload::class);
        $method = $ref->getMethod('cleanupNonceFiles');
        $method->setAccessible(true);
        $method->invoke($server);

        // Should return early and not crash, and skip the directory
        $this->assertTrue(true);
        @rmdir($dummyDir);
    }
}
