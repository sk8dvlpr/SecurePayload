<?php

declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

final class FileStreamMultipartTest extends TestCase
{
    /** @var list<string> */
    private array $tmp = [];

    protected function setUp(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium diperlukan');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            if (is_file($f)) {
                @unlink($f);
            }
        }
    }

    private function tmp(string $suffix): string
    {
        $p = sys_get_temp_dir() . '/sp_mp_' . bin2hex(random_bytes(6)) . $suffix;
        $this->tmp[] = $p;
        return $p;
    }

    public function testMultipartRoundTripHmac(): void
    {
        $secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
        $aead = base64_encode(str_repeat("\x55", 32));
        $clock = static fn (): int => 1_700_000_000;

        $client = new SecurePayload([
            'mode' => 'hmac',
            'version' => '4',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => $secret,
            'aeadKeyB64' => $aead,
            'clock' => $clock,
            'nonceGenerator' => static fn (): string => base64_encode(str_repeat("\x0a", 16)),
        ]);
        $server = new SecurePayload([
            'mode' => 'hmac',
            'version' => '4',
            'aeadKeyB64' => $aead,
            'clock' => $clock,
            'replayStore' => static fn (string $k, int $t): bool => true,
            'keyLoader' => static fn (): array => [
                'hmacSecret' => $secret,
                'aeadKeyB64' => $aead,
            ],
        ]);

        $src = $this->tmp('.bin');
        file_put_contents($src, str_repeat('Z', 5000));
        $dest = $this->tmp('.out');

        [$headers, $body, $ct] = $client->buildFileStreamMultipartRequest(
            'https://api.test/upload',
            'POST',
            $src,
            ['name' => 'z.bin']
        );

        $this->assertSame('1', $headers[SecurePayload::HX_MULTIPART] ?? null);
        $this->assertStringContainsString('multipart/form-data', $ct);
        $this->assertSame($ct, $headers['Content-Type']);

        $res = $server->verifyFileStreamMultipart($headers, $body, 'POST', '/upload', '', $dest);
        $this->assertTrue($res['ok'], $res['error'] ?? '');
        $this->assertSame(str_repeat('Z', 5000), file_get_contents($dest));
        $this->assertSame('z.bin', $res['file']['name'] ?? null);
    }

    public function testMultipartRoundTripBoth(): void
    {
        $secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
        $aead = base64_encode(str_repeat("\x56", 32));
        $clock = static fn (): int => 1_700_000_000;

        $client = new SecurePayload([
            'mode' => 'both',
            'version' => '4',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => $secret,
            'aeadKeyB64' => $aead,
            'clock' => $clock,
            'nonceGenerator' => static fn (): string => base64_encode(str_repeat("\x0b", 16)),
        ]);
        $server = new SecurePayload([
            'mode' => 'both',
            'version' => '4',
            'aeadKeyB64' => $aead,
            'clock' => $clock,
            'replayStore' => static fn (string $k, int $t): bool => true,
            'keyLoader' => static fn (): array => [
                'hmacSecret' => $secret,
                'aeadKeyB64' => $aead,
            ],
        ]);

        $src = $this->tmp('.bin');
        file_put_contents($src, "hello-multipart");
        $dest = $this->tmp('.out');

        [$headers, $body] = $client->buildFileStreamMultipartRequest(
            'https://api.test/up',
            'POST',
            $src
        );
        $res = $server->verifyFileStreamMultipart($headers, $body, 'POST', '/up', '', $dest);
        $this->assertTrue($res['ok'], $res['error'] ?? '');
        $this->assertSame('hello-multipart', file_get_contents($dest));
    }
}
