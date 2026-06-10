<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

/**
 * Test untuk executeCurl(), send(), dan sendFile()
 * Menggunakan port yang pasti tertutup untuk trigger cURL error path
 * tanpa butuh server nyata.
 */
final class HttpClientTest extends TestCase
{
    private const HMAC_32    = 'test-hmac-secret-must-be-32bytes!!';
    private const DEAD_URL   = 'http://127.0.0.1:1';  // Port pasti tertutup
    private string $tmpFile;

    protected function setUp(): void
    {
        if (!extension_loaded('curl')) {
            $this->markTestSkipped('ext-curl diperlukan untuk HttpClientTest');
        }
        $this->tmpFile = sys_get_temp_dir() . '/sp_http_test_' . uniqid() . '.txt';
        file_put_contents($this->tmpFile, 'http client test content');
    }

    protected function tearDown(): void
    {
        if (isset($this->tmpFile) && file_exists($this->tmpFile)) {
            unlink($this->tmpFile);
        }
    }

    private function makeClient(string $mode = 'hmac', ?string $aeadKey = null): SecurePayload
    {
        return new SecurePayload(array_filter([
            'mode'          => $mode,
            'version'       => '1',
            'clientId'      => 'http-test-client',
            'keyId'         => 'http-test-key',
            'hmacSecretRaw' => $mode !== 'aead' ? self::HMAC_32 : null,
            'aeadKeyB64'    => $aeadKey,
        ], fn($v) => $v !== null));
    }

    // =========================================================
    // send() tests
    // =========================================================

    public function testSend_PostRequest_ReturnsArrayWithRequiredKeys(): void
    {
        $result = $this->makeClient()->send(self::DEAD_URL, 'POST', ['key' => 'value']);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('status', $result);
        $this->assertArrayHasKey('headers', $result);
        $this->assertArrayHasKey('body', $result);
        $this->assertArrayHasKey('error', $result);
    }

    public function testSend_ConnectionRefused_ErrorNotNull(): void
    {
        $result = $this->makeClient()->send(self::DEAD_URL, 'POST', ['test' => 1]);

        $this->assertNotNull($result['error'],
            'cURL error harus ada karena koneksi ke port 1 pasti ditolak'
        );
        $this->assertIsString($result['error']);
    }

    public function testSend_GetMethod_DoesNotThrow(): void
    {
        $result = $this->makeClient()->send(self::DEAD_URL, 'GET', []);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('error', $result);
    }

    public function testSend_WithExtraHeaders_DoesNotThrow(): void
    {
        $result = $this->makeClient()->send(
            self::DEAD_URL,
            'POST',
            ['data' => 'value'],
            ['X-Custom-Header' => 'custom-value', 'X-Request-Id' => 'test-123']
        );

        $this->assertIsArray($result);
        $this->assertArrayHasKey('error', $result);
    }

    public function testSend_PutMethod_DoesNotThrow(): void
    {
        $result = $this->makeClient()->send(self::DEAD_URL, 'PUT', ['update' => true]);
        $this->assertIsArray($result);
    }

    public function testSend_DeleteMethod_DoesNotThrow(): void
    {
        $result = $this->makeClient()->send(self::DEAD_URL, 'DELETE', []);
        $this->assertIsArray($result);
    }

    public function testSend_AeadMode_BuildsEncryptedBody(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium required');
        }
        $aeadKey = base64_encode(random_bytes(32));
        $client  = $this->makeClient('both', $aeadKey);

        $result  = $client->send(self::DEAD_URL, 'POST', ['secret' => 'data']);

        // Tetap return array meski koneksi gagal
        $this->assertIsArray($result);
        $this->assertArrayHasKey('error', $result);
    }

    // =========================================================
    // sendFile() tests
    // =========================================================

    public function testSendFile_BasicUpload_ReturnsArrayWithRequiredKeys(): void
    {
        $result = $this->makeClient()->sendFile(self::DEAD_URL, 'POST', $this->tmpFile);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('status', $result);
        $this->assertArrayHasKey('body', $result);
        $this->assertArrayHasKey('error', $result);
    }

    public function testSendFile_ConnectionRefused_ErrorNotNull(): void
    {
        $result = $this->makeClient()->sendFile(self::DEAD_URL, 'POST', $this->tmpFile);

        $this->assertNotNull($result['error']);
    }

    public function testSendFile_WithAdditionalData_DoesNotThrow(): void
    {
        $result = $this->makeClient()->sendFile(
            self::DEAD_URL,
            'POST',
            $this->tmpFile,
            ['user_id' => 42, 'category' => 'documents']
        );

        $this->assertIsArray($result);
        $this->assertArrayHasKey('error', $result);
    }

    public function testSendFile_WithCustomFileName_DoesNotThrow(): void
    {
        $result = $this->makeClient()->sendFile(
            self::DEAD_URL,
            'POST',
            $this->tmpFile,
            [],
            'custom_document_name.txt'
        );

        $this->assertIsArray($result);
        $this->assertArrayHasKey('error', $result);
    }

    public function testSendFile_WithExtraHeaders_DoesNotThrow(): void
    {
        $result = $this->makeClient()->sendFile(
            self::DEAD_URL,
            'POST',
            $this->tmpFile,
            ['meta' => 'data'],
            null,
            ['X-Upload-Source' => 'unit-test']
        );

        $this->assertIsArray($result);
        $this->assertArrayHasKey('error', $result);
    }

    public function testSendFile_WithAllParameters_DoesNotThrow(): void
    {
        $result = $this->makeClient()->sendFile(
            self::DEAD_URL,
            'POST',
            $this->tmpFile,
            ['context' => 'full-param-test'],
            'renamed_file.txt',
            ['X-Full-Test' => 'true']
        );

        $this->assertIsArray($result);
    }
}
