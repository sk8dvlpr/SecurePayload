<?php

declare(strict_types=1);

namespace SecurePayload\Tests\Integration;

use PHPUnit\Framework\TestCase;
use SecurePayload\Delivery\SecureLinkIssuer;
use SecurePayload\Delivery\SecureLinkVerifier;
use SecurePayload\KMS\LocalKms;
use SecurePayload\Storage\Adapter\LocalStorageAdapter;
use SecurePayload\Storage\FileManifest;
use SecurePayload\Storage\SecureFileStorage;

/**
   * Secure Delivery end-to-end:
   * file disimpan terenkripsi (Storage M1) → link single-use diterbitkan
   * (boundTo client_001) → verifikasi OK → isi file di-stream utuh ke
   * php://temp → token sama ditolak saat dipakai ulang.
  
   * Juga memverifikasi higiene disk: streaming tidak menulis file apa pun,
   * dan retrieve() berbasis tmp+rename tidak menyisakan artefak ".tmp-".
  */
final class SecureDeliveryRoundTripTest extends TestCase
{
    private const KEK_ID = 'delivery';
    private const SECRET = 'integration-secret-0123456789abcdef';
    private const NOW = 1735689600; // clock tetap: test deterministik tanpa sleep

    /** @var array<string,string|false> */
    private array $envBackup = [];

    private string $rootDir;

    private string $destDir;

    /** @var list<string> */
    private array $tmpFiles = [];

    protected function setUp(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium diperlukan untuk storage terenkripsi');
        }
        $this->envBackup = [];
        // Pola backup/restore env seperti StorageRoundTripTest.
        $this->setEnv('SECURE_KEKS', self::KEK_ID);
        $this->setEnv('SECURE_KEK_' . self::KEK_ID . '_B64', base64_encode(random_bytes(32)));
        $this->rootDir = sys_get_temp_dir() . '/sp_delivery_blob_' . bin2hex(random_bytes(6));
        $this->destDir = sys_get_temp_dir() . '/sp_delivery_dest_' . bin2hex(random_bytes(6));
        if (!@mkdir($this->destDir, 0770, true) && !is_dir($this->destDir)) {
            self::fail("Gagal membuat direktori tujuan uji: {$this->destDir}");
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->envBackup as $key => $value) {
            if ($value === false) {
                putenv($key);
            } else {
                putenv("$key=$value");
            }
        }
        foreach ($this->tmpFiles as $f) {
            if (is_file($f)) {
                @unlink($f);
            }
        }
        $this->removeDir($this->rootDir);
        $this->removeDir($this->destDir);
    }

    private function setEnv(string $key, string $value): void
    {
        $this->envBackup[$key] = getenv($key);
        putenv("$key=$value");
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (scandir($dir) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $entry;
            is_dir($path) ? $this->removeDir($path) : @unlink($path);
        }
        @rmdir($dir);
    }

    /**
       * Daftar nama file dalam sebuah direktori (tanpa . dan ..), diurutkan.
      
       * @return list<string>
      */
    private function filesIn(string $dir): array
    {
        $entries = array_values(array_filter(
            scandir($dir) ?: [],
            static fn (string $f): bool => $f !== '.' && $f !== '..'
        ));
        sort($entries);
        return $entries;
    }

    public function testEndToEnd_StoreIssueVerifyStream_DanTokenSekaliPakai(): void
    {
        // 1. Simpan file dummy via Storage M1 (multi-chunk + ekor parsial).
        $storage = new SecureFileStorage(LocalKms::fromEnv(), new LocalStorageAdapter($this->rootDir));
        $content = "REPORT-HEADER\n" . random_bytes(150000) . "\nTAIL-MARKER";
        $src = sys_get_temp_dir() . '/sp_delivery_src_' . bin2hex(random_bytes(6)) . '.bin';
        $this->tmpFiles[] = $src;
        $this->assertNotFalse(file_put_contents($src, $content));

        $m = $storage->store($src, ['client_id' => 'client_001', 'kek_id' => self::KEK_ID]);
        $fileId = $m->fileId();
        $this->assertMatchesRegularExpression('/^[a-f0-9]{32}$/', $fileId);

        // 2. Terbitkan link single-use terikat client_001 (clock tetap).
        $issuer = new SecureLinkIssuer(self::SECRET, ['clock' => static fn (): int => self::NOW]);
        $token = $issuer->issue($fileId, 300, true, 'client_001');
        $this->assertMatchesRegularExpression(
            '/^sp1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/',
            $token,
            'Token harus URL-safe (base64url tanpa padding).'
        );

        // 3. Verifikasi OK oleh pemegang sah.
        $seen = []; // replay store in-memory: key -> ttl
        $store = static function (string $key, int $ttl) use (&$seen): bool {
            if (array_key_exists($key, $seen)) {
                return false;
            }
            $seen[$key] = $ttl;
            return true;
        };
        $denied = [];
        $verifier = new SecureLinkVerifier(
            self::SECRET,
            $store,
            [
                'clock' => static fn (): int => self::NOW,
                'onSecurityEvent' => static function (string $event, array $context) use (&$denied): void {
                    if ($event === 'file_access_denied') {
                        $denied[] = $context;
                    }
                },
            ]
        );

        $check = $verifier->verify($fileId, $token, 'client_001');
        $this->assertTrue($check['ok'], 'Verifikasi pertama harus lolos.');
        $this->assertSame(200, $check['status']);
        $claims = $check['claims'] ?? [];
        $this->assertSame($fileId, $claims['file_id']);
        $this->assertTrue($claims['su']);
        $this->assertSame('client_001', $claims['bound_to']);

        // 4. Stream isi file ke php://temp — konten identik byte-per-byte.
        $filesBeforeStream = $this->filesIn($this->destDir);
        $this->assertSame([], $filesBeforeStream);

        $sink = fopen('php://temp', 'w+b');
        $this->assertNotFalse($sink);
        try {
            $storage->retrieveStream($m, static function (string $chunk) use ($sink): void {
                fwrite($sink, $chunk);
            });
            rewind($sink);
            $delivered = (string) stream_get_contents($sink);
        } finally {
            fclose($sink);
        }
        $this->assertTrue(hash_equals($content, $delivered), 'Isi yang di-stream harus identik dengan sumber.');
        $this->assertSame(
            $filesBeforeStream,
            $this->filesIn($this->destDir),
            'Streaming delivery tidak boleh menulis file apa pun ke disk.'
        );

        // 5. retrieve() berbasis tmp+rename juga tidak menyisakan artefak tmp.
        $destPath = $this->destDir . DIRECTORY_SEPARATOR . 'out.bin';
        $storage->retrieve($m, $destPath);
        $afterRetrieve = $this->filesIn($this->destDir);
        $this->assertSame(['out.bin'], $afterRetrieve, 'Direktori tujuan hanya boleh berisi hasil retrieve.');
        $leftovers = array_values(array_filter($afterRetrieve, static fn (string $f): bool => str_contains($f, '.tmp-')));
        $this->assertSame([], $leftovers, 'Tidak boleh ada file sementara tertinggal.');
        $this->assertTrue(hash_equals($content, (string) file_get_contents($destPath)));

        // Direktori blob adapter juga bersih dari tmp (hanya blob ciphertext).
        $blobEntries = $this->filesIn($this->rootDir);
        $this->assertSame([$fileId], $blobEntries, 'Blob storage hanya berisi ciphertext milik manifest.');

        // 6. Token sama dipakai ulang → ditolak single-use.
        $replay = $verifier->verify($fileId, $token, 'client_001');
        $this->assertFalse($replay['ok']);
        $this->assertSame(403, $replay['status']);
        $this->assertSame('token_reused', $replay['error']);
        $this->assertCount(1, $denied, 'Tepat satu event denied (pemakaian ulang).');
        $this->assertSame(['reason' => 'token_reused', 'file_id' => $fileId], $denied[0]);

        // 7. Manifest tetap konsisten untuk pemanggilan berikutnya.
        $this->assertInstanceOf(FileManifest::class, $m);
    }
}
