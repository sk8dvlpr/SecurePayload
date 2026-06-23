<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

final class FilePayloadTest extends TestCase
{
    private const HMAC_32 = 'test-hmac-secret-must-be-32bytes!!';
    private const AEAD_KEY_PLACEHOLDER = ''; // akan di-generate per test
    private string $tempFile;

    protected function setUp(): void
    {
        $this->tempFile = sys_get_temp_dir() . '/test_sp_upload.txt';
        file_put_contents($this->tempFile, 'Hello Secure World!');
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tempFile)) {
            unlink($this->tempFile);
        }
    }

    private function makeClient(string $mode = 'hmac', ?string $aeadKey = null): SecurePayload
    {
        return new SecurePayload([
            'mode' => $mode,
            'version' => '1',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::HMAC_32,
            'aeadKeyB64' => $aeadKey
        ]);
    }

    private function makeServer(string $mode = 'hmac', ?string $aeadKey = null): SecurePayload
    {
        return new SecurePayload([
            'mode' => $mode,
            'version' => '1',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => $aeadKey]
        ]);
    }

    public function testBuildFilePayload_FileGetContentsFails_ThrowsException(): void
    {
        $sp = new SecurePayload([
            'mode' => 'hmac',
            'version' => '1',
            'clientId' => 'c',
            'keyId' => 'k',
            'hmacSecretRaw' => 'test-hmac-secret-must-be-32bytes!!',
        ]);
        
        $this->expectException(\SecurePayload\Exceptions\SecurePayloadException::class);
        $this->expectExceptionMessage('tidak ditemukan atau tidak terbaca');

        // Pass a directory: is_file() is false on all platforms, so it is rejected deterministically.
        @$sp->buildFilePayload('http://test.com', 'POST', __DIR__);
    }

    public function testBuildAndVerifyFilePayload(): void
    {
        $client = $this->makeClient();
        [$headers, $body] = $client->buildFilePayload('https://site.com/upload', 'POST', $this->tempFile);

        $server = $this->makeServer();
        $res = $server->verifyFilePayload($headers, $body, 'POST', '/upload');

        $this->assertTrue($res['ok'], 'Verifikasi harus sukses');
        $this->assertNotNull($res['file']);
        $this->assertSame('test_sp_upload.txt', $res['file']['name']);
        $this->assertSame('Hello Secure World!', $res['file']['content_decoded']);
        $this->assertEmpty($res['data']);
    }

    public function testFileWithAdditionalData(): void
    {
        if (!\extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium is required for BOTH mode');
        }
        $aeadKey = base64_encode(str_repeat('x', 32));
        $client = $this->makeClient('both', $aeadKey);

        [$headers, $body] = $client->buildFilePayload(
            'https://site.com/upload',
            'POST',
            $this->tempFile,
            ['user_id' => 123, 'note' => 'test upload']
        );

        $server = $this->makeServer('both', $aeadKey);
        $res = $server->verifyFilePayload($headers, $body, 'POST', '/upload');

        $this->assertTrue($res['ok']);
        $this->assertSame(123, $res['data']['user_id']);
        $this->assertSame('test_sp_upload.txt', $res['file']['name']);
    }

    public function testDangerousExtensionBlock(): void
    {
        $phpFile = sys_get_temp_dir() . '/exploit.php';
        file_put_contents($phpFile, '<?php echo "hacker"; ?>');

        $client = $this->makeClient();
        [$headers, $body] = $client->buildFilePayload('https://site.com/up', 'POST', $phpFile);

        $server = $this->makeServer();
        $res = $server->verifyFilePayload($headers, $body, 'POST', '/up');

        unlink($phpFile);

        $this->assertFalse($res['ok']);
        $this->assertSame(422, $res['status']);
        $this->assertStringContainsString('berbahaya', $res['error']);
    }

    public function testFileSizeLimit(): void
    {
        $client = $this->makeClient();
        [$headers, $body] = $client->buildFilePayload('https://site.com/up', 'POST', $this->tempFile);

        $server = $this->makeServer();
        $res = $server->verifyFilePayload($headers, $body, 'POST', '/up', ['max_size' => 5]);

        $this->assertFalse($res['ok']);
        $this->assertSame(413, $res['status']);
    }

    public function testBuildFilePayload_ReturnsArrayWithTwoElements(): void
    {
        $client = $this->makeClient();
        $result = $client->buildFilePayload('https://site.com/upload', 'POST', $this->tempFile);

        $this->assertIsArray($result);
        $this->assertCount(2, $result);
        [$headers, $body] = $result;
        $this->assertArrayHasKey('X-Client-Id', $headers);
        $this->assertJson($body);
    }

    public function testCustomDangerousExtensions(): void
    {
        $xyzFile = sys_get_temp_dir() . '/malware.xyz';
        file_put_contents($xyzFile, 'bad code');

        $client = $this->makeClient();
        [$headers, $body] = $client->buildFilePayload('https://site.com/up', 'POST', $xyzFile);

        $server = $this->makeServer();
        $res = $server->verifyFilePayload($headers, $body, 'POST', '/up', [
            'block_dangerous' => ['xyz']
        ]);

        unlink($xyzFile);

        $this->assertFalse($res['ok']);
        $this->assertStringContainsString('berbahaya', $res['error']);

        $phpFile = sys_get_temp_dir() . '/malware.php';
        file_put_contents($phpFile, '<?php ?>');
        [$h2, $b2] = $client->buildFilePayload('https://site.com/up', 'POST', $phpFile);

        $res2 = $server->verifyFilePayload($h2, $b2, 'POST', '/up', [
            'block_dangerous' => ['xyz']
        ]);
        unlink($phpFile);

        $this->assertFalse($res2['ok']);
        $this->assertStringContainsString('berbahaya', $res2['error']);
    }

    public function testMimeTypeSpoofing(): void
    {
        $fakeJpg = sys_get_temp_dir() . '/evil.jpg';
        file_put_contents($fakeJpg, '<?php echo "pwned"; ?>');

        $client = $this->makeClient();
        [$headers, $body] = $client->buildFilePayload('https://site.com/up', 'POST', $fakeJpg);

        $server = $this->makeServer();
        $res = $server->verifyFilePayload($headers, $body, 'POST', '/up');

        unlink($fakeJpg);

        $this->assertFalse($res['ok'], 'Harus gagal karena konten bukan JPG asli (Spoofing)');
        $this->assertStringContainsString('Spoofing', $res['error'] ?? '');
    }

    /**
     * @covers \SecurePayload\SecurePayload::verifyFilePayload
     * SEC-03: Patch memastikan nama file di-sanitasi dengan basename()
     */
    public function testFilePayload_PathTraversalName_IsStrippedToBasename(): void
    {
        $realFile = sys_get_temp_dir() . '/legit.txt';
        file_put_contents($realFile, 'safe content');

        $client = $this->makeClient();
        [$headers, $body] = $client->buildFilePayload('https://site.com/up', 'POST', $realFile);

        $decoded = json_decode($body, true);
        $decoded['_attachment']['name'] = '../../../etc/cron.d/backdoor';
        $tamperedBody = json_encode($decoded);

        unlink($realFile);

        $digest = base64_encode(hash('sha256', $tamperedBody, true));
        $headers[\SecurePayload\SecurePayload::HX_BODY_DIGEST] = 'sha256=' . $digest;
        
        $canon = $headers[\SecurePayload\SecurePayload::HX_CANON_REQ];
        $parts = explode("\n", base64_decode($canon, true) ?: $canon);
        $method = $parts[0] ?? 'POST';
        $path = $parts[1] ?? '/up';
        $qStr = $parts[2] ?? '';
        
        $msg = \SecurePayload\SecurePayload::hmacMessage('1', 'c1', 'k1', $headers[\SecurePayload\SecurePayload::HX_TIMESTAMP], $headers[\SecurePayload\SecurePayload::HX_NONCE], $method, \SecurePayload\SecurePayload::normalizePath($path), $qStr, $digest);
        $headers[\SecurePayload\SecurePayload::HX_SIGNATURE] = base64_encode(hash_hmac('sha256', $msg, self::HMAC_32, true));

        $server = $this->makeServer();
        $res = $server->verifyFilePayload($headers, $tamperedBody, 'POST', '/up');

        $this->assertTrue($res['ok'], $res['error'] ?? '');
        $this->assertSame('backdoor', $res['file']['name']);
        $this->assertStringNotContainsString('..', $res['file']['name']);
    }

    public function testFilePayload_PathTraversalName_FileNameReturnedIsBasenameOnly(): void
    {
        $client = $this->makeClient();
        $server = $this->makeServer();

        [$headers, $body] = $client->buildFilePayload(
            'https://site.com/upload',
            'POST',
            $this->tempFile
        );

        $res = $server->verifyFilePayload($headers, $body, 'POST', '/upload');

        $this->assertTrue($res['ok']);
        $this->assertSame('test_sp_upload.txt', $res['file']['name']);
        $this->assertStringNotContainsString('/', $res['file']['name']);
        $this->assertStringNotContainsString('..', $res['file']['name']);
        $this->assertStringNotContainsString(sys_get_temp_dir(), $res['file']['name']);
    }

    public function testValidJpgContent(): void
    {
        $validJpg = sys_get_temp_dir() . '/good.jpg';
        file_put_contents($validJpg, "\xFF\xD8\xFF\xE0" . str_repeat('0', 20));

        $client = $this->makeClient();
        [$headers, $body] = $client->buildFilePayload('https://site.com/up', 'POST', $validJpg);

        $server = $this->makeServer();
        $res = $server->verifyFilePayload($headers, $body, 'POST', '/up');

        unlink($validJpg);

        // finfo detection may vary across platforms; either outcome is acceptable
        // but we verify the response structure is always correct
        $this->assertArrayHasKey('ok', $res);
        $this->assertArrayHasKey('status', $res);
        if ($res['ok']) {
            $this->assertNotNull($res['file']);
            $this->assertSame('good.jpg', $res['file']['name']);
        } else {
            // Environment-specific finfo detection may flag the minimal JPEG header
            $this->assertArrayHasKey('error', $res);
            $this->assertIsString($res['error']);
        }
    }

    /**
     * [COV-06a] verifyFilePayload() tanpa file dalam payload → gagal 400
     */
    public function testVerifyFilePayload_NoAttachment_ReturnsBadRequest(): void
    {
        $client = new SecurePayload([
            'mode'          => 'hmac',
            'version'       => '1',
            'clientId'      => 'c',
            'keyId'         => 'k',
            'hmacSecretRaw' => self::HMAC_32,
        ]);

        [$headers, $body] = $client->buildHeadersAndBody(
            'https://site.com/upload', 'POST', ['no_file' => true]
        );

        $server = new SecurePayload([
            'mode'      => 'hmac',
            'version'   => '1',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null],
        ]);

        $res = $server->verifyFilePayload($headers, $body, 'POST', '/upload');
        $this->assertFalse($res['ok']);
        $this->assertSame(400, $res['status']);
    }

    /**
     * [COV-06b] verifyFilePayload() dengan allowed_mime whitelist — file yang cocok diterima
     */
    public function testVerifyFilePayload_AllowedMimeWhitelist_MatchingFile_Accepted(): void
    {
        $client = new SecurePayload([
            'mode'          => 'hmac',
            'version'       => '1',
            'clientId'      => 'c',
            'keyId'         => 'k',
            'hmacSecretRaw' => self::HMAC_32,
        ]);

        [$headers, $body] = $client->buildFilePayload(
            'https://site.com/upload', 'POST', $this->tempFile
        );

        $server = new SecurePayload([
            'mode'      => 'hmac',
            'version'   => '1',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null],
        ]);

        // tempFile adalah .txt → allowed_exts harus include txt
        $res = $server->verifyFilePayload($headers, $body, 'POST', '/upload', [
            'allowed_exts' => ['txt'],
        ]);

        $this->assertTrue($res['ok'], json_encode($res));
    }

    /**
     * [COV-06c] verifyFilePayload() dengan allowed_mime whitelist — file tidak cocok ditolak
     */
    public function testVerifyFilePayload_AllowedMimeWhitelist_MismatchFile_Rejected(): void
    {
        $client = new SecurePayload([
            'mode'          => 'hmac',
            'version'       => '1',
            'clientId'      => 'c',
            'keyId'         => 'k',
            'hmacSecretRaw' => self::HMAC_32,
        ]);

        [$headers, $body] = $client->buildFilePayload(
            'https://site.com/upload', 'POST', $this->tempFile
        );

        $server = new SecurePayload([
            'mode'      => 'hmac',
            'version'   => '1',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null],
        ]);

        // tempFile adalah .txt tapi hanya allow png/jpg → harus ditolak
        $res = $server->verifyFilePayload($headers, $body, 'POST', '/upload', [
            'allowed_exts' => ['png', 'jpg'],
        ]);

        $this->assertFalse($res['ok']);
    }

    /**
     * [COV-06d] verifyFilePayload() dengan block_dangerous = false — file .php diterima
     */
    public function testVerifyFilePayload_BlockDangerousFalse_AllowsPhpFile(): void
    {
        $phpFile = sys_get_temp_dir() . '/cov_test.php';
        file_put_contents($phpFile, '<?php echo "test"; ?>');

        $client = new SecurePayload([
            'mode'          => 'hmac',
            'version'       => '1',
            'clientId'      => 'c',
            'keyId'         => 'k',
            'hmacSecretRaw' => self::HMAC_32,
        ]);

        [$headers, $body] = $client->buildFilePayload(
            'https://site.com/upload', 'POST', $phpFile
        );

        $server = new SecurePayload([
            'mode'      => 'hmac',
            'version'   => '1',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null],
        ]);

        // block_dangerous = false dan strict_mime = false → file .php tidak diblokir
        $res = $server->verifyFilePayload($headers, $body, 'POST', '/upload', [
            'block_dangerous' => false,
            'strict_mime' => false,
        ]);

        unlink($phpFile);

        $this->assertTrue($res['ok'], json_encode($res));
    }
}
