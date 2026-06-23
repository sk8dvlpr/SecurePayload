<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Integration;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

/**
 * Integrasi Phase 6 — round-trip transfer file streaming (secretstream).
 */
final class FileStreamRoundTripTest extends TestCase
{
    /** @var list<string> */
    private array $tmp = [];

    protected function setUp(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium diperlukan untuk streaming AEAD');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            if (is_file($f)) {
                @unlink($f);
            }
        }
        $this->tmp = [];
    }

    private function tmpPath(string $suffix): string
    {
        $p = sys_get_temp_dir() . '/sp_stream_' . bin2hex(random_bytes(6)) . $suffix;
        $this->tmp[] = $p;
        return $p;
    }

    private function sp(bool $derive = false): SecurePayload
    {
        return new SecurePayload([
            'mode' => 'aead',
            'aeadKeyB64' => base64_encode(str_repeat("\x44", 32)),
            'deriveKeys' => $derive,
        ]);
    }

    public function testRoundTripMultiChunk(): void
    {
        $src = $this->tmpPath('.bin');
        $content = str_repeat("x", 200000); // > 3 chunk @ 64KiB
        file_put_contents($src, $content);

        $sp = $this->sp();
        $enc = $this->tmpPath('.enc');
        $manifest = $sp->buildFileStream($src, $enc, ['name' => 'big.bin']);

        $this->assertSame(SecurePayload::STREAM_ALG, $manifest['alg']);
        $this->assertSame(200000, $manifest['size']);
        $this->assertSame('big.bin', $manifest['name']);
        $this->assertStringStartsWith('sha256=', $manifest['cipher_digest']);

        $dec = $this->tmpPath('.out');
        $res = $sp->verifyFileStream($enc, $manifest, $dec);

        $this->assertTrue($res['ok'], $res['error'] ?? '');
        $this->assertSame(200000, $res['file']['size']);
        $this->assertSame($content, file_get_contents($dec), 'Plaintext hasil dekripsi harus identik dengan sumber.');
    }

    public function testRoundTripExactChunkMultiple(): void
    {
        $src = $this->tmpPath('.bin');
        file_put_contents($src, str_repeat("y", 2048)); // tepat 2 x chunk 1024

        $sp = $this->sp();
        $enc = $this->tmpPath('.enc');
        $manifest = $sp->buildFileStream($src, $enc, [], 1024);

        $dec = $this->tmpPath('.out');
        $res = $sp->verifyFileStream($enc, $manifest, $dec);
        $this->assertTrue($res['ok'], $res['error'] ?? '');
        $this->assertSame(file_get_contents($src), file_get_contents($dec));
    }

    public function testRoundTripEmptyFile(): void
    {
        $src = $this->tmpPath('.bin');
        file_put_contents($src, '');

        $sp = $this->sp();
        $enc = $this->tmpPath('.enc');
        $manifest = $sp->buildFileStream($src, $enc);
        $this->assertSame(0, $manifest['size']);

        $dec = $this->tmpPath('.out');
        $res = $sp->verifyFileStream($enc, $manifest, $dec);
        $this->assertTrue($res['ok'], $res['error'] ?? '');
        $this->assertSame('', file_get_contents($dec));
    }

    public function testRoundTripWithDeriveKeys(): void
    {
        $src = $this->tmpPath('.bin');
        $content = str_repeat("z", 150000);
        file_put_contents($src, $content);

        $client = $this->sp(true);
        $server = $this->sp(true);
        $enc = $this->tmpPath('.enc');
        $manifest = $client->buildFileStream($src, $enc, ['name' => 'data.bin']);

        $dec = $this->tmpPath('.out');
        $res = $server->verifyFileStream($enc, $manifest, $dec);
        $this->assertTrue($res['ok'], $res['error'] ?? '');
        $this->assertSame($content, file_get_contents($dec));
    }
}
