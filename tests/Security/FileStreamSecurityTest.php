<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Security;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

/**
 * Regresi keamanan Phase 6 — transfer file streaming (secretstream).
 *
 * Memastikan:
 *  - chunk yang dirusak ditolak (tag Poly1305),
 *  - truncation & append ditolak (TAG_FINAL tunggal & wajib),
 *  - digest ciphertext yang tidak cocok ditolak,
 *  - kunci salah gagal mendekripsi,
 *  - MIME spoofing & ekstensi berbahaya ditolak,
 *  - GAGAL-TERTUTUP: file plaintext parsial dihapus saat verifikasi gagal.
 */
final class FileStreamSecurityTest extends TestCase
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
        $p = sys_get_temp_dir() . '/sp_streamsec_' . bin2hex(random_bytes(6)) . $suffix;
        $this->tmp[] = $p;
        return $p;
    }

    private function sp(string $keyByte = "\x44"): SecurePayload
    {
        return new SecurePayload([
            'mode' => 'aead',
            'aeadKeyB64' => base64_encode(str_repeat($keyByte, 32)),
        ]);
    }

    /** @return array{0:SecurePayload,1:string,2:array<string,mixed>} [sp, encPath, manifest] */
    private function makeEncrypted(string $content, string $name = 'data.bin', int $chunk = 65536): array
    {
        $src = $this->tmpPath('.bin');
        file_put_contents($src, $content);
        $sp = $this->sp();
        $enc = $this->tmpPath('.enc');
        $manifest = $sp->buildFileStream($src, $enc, ['name' => $name], $chunk);
        return [$sp, $enc, $manifest];
    }

    public function testTamperedChunkRejectedAndFailClosed(): void
    {
        [$sp, $enc, $manifest] = $this->makeEncrypted(random_bytes(5000));

        // Balik satu byte di dalam ciphertext (lewati prefix panjang 4-byte).
        $raw = file_get_contents($enc);
        $raw[10] = $raw[10] === "\x00" ? "\x01" : "\x00";
        file_put_contents($enc, $raw);

        $dec = $this->tmpPath('.out');
        $res = $sp->verifyFileStream($enc, $manifest, $dec);

        $this->assertFalse($res['ok'], 'Chunk yang dirusak harus ditolak.');
        $this->assertStringContainsString('mendekripsi', $res['error']);
        $this->assertFileDoesNotExist($dec, 'Plaintext parsial harus dihapus (fail-closed).');
    }

    public function testTruncatedStreamRejected(): void
    {
        [$sp, $enc, $manifest] = $this->makeEncrypted(random_bytes(5000));

        // Potong beberapa byte terakhir → frame terakhir tidak lengkap.
        $raw = file_get_contents($enc);
        file_put_contents($enc, substr($raw, 0, strlen($raw) - 5));

        $dec = $this->tmpPath('.out');
        $res = $sp->verifyFileStream($enc, $manifest, $dec);
        $this->assertFalse($res['ok'], 'Stream terpotong harus ditolak.');
        $this->assertFileDoesNotExist($dec);
    }

    public function testAppendedDataRejected(): void
    {
        [$sp, $enc, $manifest] = $this->makeEncrypted(random_bytes(3000));

        // Tambahkan frame palsu setelah penanda akhir.
        $raw = file_get_contents($enc);
        $fakeFrame = pack('N', 20) . str_repeat("\x00", 20);
        file_put_contents($enc, $raw . $fakeFrame);

        $dec = $this->tmpPath('.out');
        $res = $sp->verifyFileStream($enc, $manifest, $dec);
        $this->assertFalse($res['ok'], 'Data setelah penanda akhir harus ditolak.');
        $this->assertStringContainsString('append', $res['error']);
        $this->assertFileDoesNotExist($dec);
    }

    public function testCipherDigestMismatchRejected(): void
    {
        [$sp, $enc, $manifest] = $this->makeEncrypted(random_bytes(4000));

        // File utuh, tapi manifest digest dipalsukan.
        $manifest['cipher_digest'] = 'sha256=' . base64_encode(str_repeat("\x00", 32));

        $dec = $this->tmpPath('.out');
        $res = $sp->verifyFileStream($enc, $manifest, $dec);
        $this->assertFalse($res['ok'], 'Digest ciphertext yang tidak cocok harus ditolak.');
        $this->assertStringContainsString('Digest', $res['error']);
        $this->assertFileDoesNotExist($dec);
    }

    public function testWrongKeyRejected(): void
    {
        [, $enc, $manifest] = $this->makeEncrypted(random_bytes(4000));

        $other = $this->sp("\x55"); // kunci berbeda
        $dec = $this->tmpPath('.out');
        $res = $other->verifyFileStream($enc, $manifest, $dec);
        $this->assertFalse($res['ok'], 'Kunci salah harus gagal mendekripsi.');
        $this->assertFileDoesNotExist($dec);
    }

    public function testMimeSpoofRejected(): void
    {
        // Konten skrip PHP, tetapi diberi nama .jpg.
        [$sp, $enc, $manifest] = $this->makeEncrypted("<?php echo 'x'; ?>\n" . str_repeat('A', 200), 'evil.jpg');

        $dec = $this->tmpPath('.out');
        $res = $sp->verifyFileStream($enc, $manifest, $dec, ['strict_mime' => true]);
        $this->assertFalse($res['ok'], 'Spoofing MIME harus ditolak.');
        $this->assertStringContainsString('Spoofing', $res['error']);
        $this->assertFileDoesNotExist($dec, 'Plaintext berbahaya tidak boleh tersisa di disk.');
    }

    public function testDangerousExtensionRejected(): void
    {
        [$sp, $enc, $manifest] = $this->makeEncrypted(str_repeat('A', 100), 'shell.php');

        $dec = $this->tmpPath('.out');
        $res = $sp->verifyFileStream($enc, $manifest, $dec);
        $this->assertFalse($res['ok'], 'Ekstensi berbahaya harus ditolak.');
        $this->assertStringContainsString('berbahaya', $res['error']);
    }
}
