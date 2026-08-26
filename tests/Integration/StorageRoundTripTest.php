<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Integration;

use PHPUnit\Framework\TestCase;
use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\KMS\LocalKms;
use SecurePayload\Storage\Adapter\LocalStorageAdapter;
use SecurePayload\Storage\FileManifest;
use SecurePayload\Storage\SecureFileStorage;
use SecurePayload\SecurePayload;

/**
   * round-trip file besar (~5MB) multi-chunk dan
   * fail-closed cleanup: manifest korup tidak boleh meninggalkan file
   * parsial di path tujuan.
  */
final class StorageRoundTripTest extends TestCase
{
    private const KEK_ID = 'itest';

    /** @var array<string,string|false> */
    private array $envBackup = [];

    private string $rootDir;

    /** @var list<string> */
    private array $tmpFiles = [];

    protected function setUp(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium diperlukan untuk storage terenkripsi');
        }
        $this->envBackup = [];
        $this->setEnv('SECURE_KEKS', self::KEK_ID);
        $this->setEnv('SECURE_KEK_' . self::KEK_ID . '_B64', base64_encode(random_bytes(32)));
        $this->rootDir = sys_get_temp_dir() . '/sp_roundtrip_' . bin2hex(random_bytes(6));
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
        if (is_dir($this->rootDir)) {
            foreach (scandir($this->rootDir) ?: [] as $entry) {
                if ($entry !== '.' && $entry !== '..') {
                    @unlink($this->rootDir . DIRECTORY_SEPARATOR . $entry);
                }
            }
            @rmdir($this->rootDir);
        }
    }

    private function setEnv(string $key, string $value): void
    {
        $this->envBackup[$key] = getenv($key);
        putenv("$key=$value");
    }

    private function storage(): SecureFileStorage
    {
        return new SecureFileStorage(LocalKms::fromEnv(), new LocalStorageAdapter($this->rootDir));
    }

    /**
       * Bangun file pseudo-random ~5MB: 80 chunk × 64KB + ekor parsial
       * 33333 byte agar batas akhir TIDAK rata dengan ukuran chunk/frame.
      */
    private function bigContentPath(): string
    {
        $p = sys_get_temp_dir() . '/sp_big_' . bin2hex(random_bytes(6)) . '.bin';
        $fh = fopen($p, 'wb');
        if ($fh === false) {
            self::fail("Gagal membuat file uji besar: $p");
        }
        $total = 0;
        for ($i = 0; $i < 80; $i++) {
            $chunk = random_bytes(65536);
            fwrite($fh, $chunk);
            $total += strlen($chunk);
        }
        $tail = random_bytes(33333);
        fwrite($fh, $tail);
        $total += strlen($tail);
        fclose($fh);
        $this->tmpFiles[] = $p;
        $this->assertSame(80 * 65536 + 33333, $total);
        return $p;
    }

    public function testRoundTrip5MB_MultiChunk_ByteIdentik(): void
    {
        $storage = $this->storage();
        $src = $this->bigContentPath();
        $m = $storage->store($src, ['client_id' => 'ci', 'kek_id' => self::KEK_ID]);

        $expectedSize = 80 * 65536 + 33333;
        $this->assertSame($expectedSize, $m->size());
        $this->assertSame('sha256=', substr($m->cipherDigest(), 0, 7));

        // Blob harus multi-frame: > plaintext karena header+tag per chunk.
        $blobLen = filesize($this->rootDir . DIRECTORY_SEPARATOR . $m->fileId());
        $this->assertIsInt($blobLen);
        $this->assertGreaterThan($expectedSize, $blobLen, 'Blob ciphertext harus memuat header + banyak frame.');

        $dest = $src . '.out';
        $this->tmpFiles[] = $dest;
        $res = $storage->retrieve($m, $dest);
        $this->assertSame($expectedSize, $res['size']);

        $hashSrc = hash_file('sha256', $src);
        $hashDest = hash_file('sha256', $dest);
        $this->assertNotFalse($hashSrc);
        $this->assertNotFalse($hashDest);
        $this->assertTrue(hash_equals((string) $hashSrc, (string) $hashDest), 'SHA-256 file hasil retrieve harus identik dengan sumber.');
    }

    public function testRetrieveStream_FileBesar_TotalByteSesuai(): void
    {
        $storage = $this->storage();
        $src = $this->bigContentPath();
        $m = $storage->store($src, ['client_id' => 'ci', 'kek_id' => self::KEK_ID]);

        $expectedSize = 80 * 65536 + 33333;
        $total = 0;
        $chunks = 0;
        $lastLen = -1;
        $storage->retrieveStream($m, static function (string $chunk) use (&$total, &$chunks, &$lastLen): void {
            $total += strlen($chunk);
            $chunks++;
            $lastLen = strlen($chunk);
        });

        $this->assertSame($expectedSize, $total);
        $this->assertSame(81, $chunks, '80 chunk penuh + 1 ekor parsial @ sink 64KB.');
        $this->assertSame(33333, $lastLen, 'Potongan terakhir harus berisi ekor parsial.');
    }

    public function testRoundTrip_StreamDenganWatermark_EndToEnd(): void
    {
        $events = [];
        $storage = new SecureFileStorage(LocalKms::fromEnv(), new LocalStorageAdapter($this->rootDir), [
            'onSecurityEvent' => static function (string $event) use (&$events): void {
                $events[$event] = ($events[$event] ?? 0) + 1;
            },
        ]);
        $src = $this->bigContentPath();
        $m = $storage->store($src, ['client_id' => 'ci', 'kek_id' => self::KEK_ID]);

        $requester = ['user_id' => 'u-e2e', 'unit' => 'forensik'];
        $out = '';
        $chunks = 0;
        $storage->retrieveStream(
            $m,
            static function (string $chunk) use (&$out, &$chunks): void {
                $out .= $chunk;
                $chunks++;
            },
            [
                'requester' => $requester,
                'beforeStream' => static function (string $plain, FileManifest $mm, array $ctx): string {
                    /** @var array{file_id:string,requester:array<string,string>} $ctx */
                    $r = $ctx['requester']['user_id'];
                    return "SP-WATERMARK v1 user={$r} file={$ctx['file_id']}\n" . $plain;
                },
            ]
        );

        // Bandingkan terhadap watermark yang dihitung independen dari isi sumber.
        $original = (string) file_get_contents($src);
        $expectedPrefix = "SP-WATERMARK v1 user=u-e2e file={$m->fileId()}\n";
        $expected = $expectedPrefix . $original;

        $this->assertSame(strlen($expected), strlen($out), 'Total byte stream = watermark header + plaintext asli.');
        $this->assertTrue(hash_equals($expected, $out), 'Stream end-to-end harus = prefix watermark + konten asli utuh.');
        // 5.276.213 byte plaintext + ekor watermark tetap menghasilkan 81 chunk @ 64KB.
        $this->assertSame(81, $chunks);
        $this->assertSame('SP-WATERMARK v1', substr($out, 0, 15), 'Chunk pertama diawali watermark (hook jalan sebelum sink).');

        $this->assertSame(1, $events[SecurePayload::EVENT_FILE_WATERMARKED] ?? 0, 'Event file_watermarked wajib tercatat sekali pada round-trip sukses.');
    }

    public function testManifestKorup_RetrieveGagal_TidakAdaFileParsial(): void
    {
        $storage = $this->storage();
        $src = $this->bigContentPath();
        $m = $storage->store($src, ['client_id' => 'ci', 'kek_id' => self::KEK_ID]);

        // Korupkan digest di manifest (simulasi manifest rusak di DB aplikasi).
        $data = $m->toArray();
        $data['cipher_digest'] = 'sha256=' . base64_encode(str_repeat("\x00", 32));
        $corrupt = FileManifest::fromArray($data);

        $dest = sys_get_temp_dir() . '/sp_dest_' . bin2hex(random_bytes(6)) . '.out';
        $this->tmpFiles[] = $dest;

        try {
            $storage->retrieve($corrupt, $dest);
            self::fail('Retrieve dengan manifest korup wajib gagal.');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::UNPROCESSABLE, $e->getCode());
        }

        $this->assertFileDoesNotExist($dest, 'Tidak boleh ada file parsial tersisa di destPath.');

        // Direktori blob storage juga bersih dari artefak tmp adapter.
        $leftovers = array_values(array_filter(
            scandir($this->rootDir) ?: [],
            static fn (string $f): bool => str_contains($f, '.tmp-')
        ));
        $this->assertSame([], $leftovers, 'Adapter tidak boleh meninggalkan file tmp.');
    }

    public function testBlobKorup_DigestDisesuaikan_GagalDiAead_TanpaFileParsial(): void
    {
        $storage = $this->storage();

        $src = sys_get_temp_dir() . '/sp_mid_' . bin2hex(random_bytes(6)) . '.bin';
        file_put_contents($src, random_bytes(300000)); // multi-frame
        $this->tmpFiles[] = $src;

        $m = $storage->store($src, ['client_id' => 'ci', 'kek_id' => self::KEK_ID]);

        // Korupkan blob langsung di adapter lalu sesuaikan digest manifest
        // agar lolos gerbang digest — dekripsi wajib tetap gagal di AEAD.
        // Offset 24(header)+4(len)+10 pasti berada DI DALAM cipher frame pertama.
        $adapter = new LocalStorageAdapter($this->rootDir);
        $blob = $adapter->get($m->fileId());
        $mid = 24 + 4 + 10;
        $this->assertLessThan(strlen($blob), $mid);
        $blob[$mid] = $blob[$mid] ^ "\x01";
        $adapter->put($m->fileId(), $blob);

        $data = $m->toArray();
        $data['cipher_digest'] = 'sha256=' . base64_encode(hash('sha256', $blob, true));
        $tamperedManifest = FileManifest::fromArray($data);

        $dest = $src . '.out';
        $this->tmpFiles[] = $dest;

        try {
            $storage->retrieve($tamperedManifest, $dest);
            self::fail('Dekripsi blob yang dimodifikasi wajib gagal di AEAD.');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::UNAUTHORIZED, $e->getCode());
        }

        $this->assertFileDoesNotExist($dest, 'AEAD failure tidak boleh meninggalkan file parsial.');
    }
}
