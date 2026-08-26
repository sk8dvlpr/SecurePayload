<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Security;

use PHPUnit\Framework\TestCase;
use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\KMS\LocalKms;
use SecurePayload\Storage\Adapter\LocalStorageAdapter;
use SecurePayload\Storage\FileManifest;
use SecurePayload\Storage\SecureFileStorage;

/**
 * invarian keamanan SecureFileStorage:
 *
 * 1. FAIL-CLOSED TAMPER: bitflip satu bit di blob ciphertext (header offset 0,
 *    tengah frame, byte terakhir) WAJIB membuat retrieve gagal — baik lewat
 *    gerbang cipher_digest (dicek dengan hash_equals SEBELUM dekripsi) maupun
 *    gerbang AEAD secretstream bila digest disesuaikan penyerang.
 * 2. BINDING AAD: wrapped DEK terikat file_id+kek_id+purpose. Substitusi
 *    wrapped_dek_b64 antar manifest dua file berbeda, atau manipulasi
 *    aad_context di manifest, wajib gagal unwrap (UNAUTHORIZED).
 * 3. DIGEST GATE: cipher_digest yang dimodifikasi di manifest wajib ditolak
 *    sebelum ada upaya dekripsi.
 * 4. NO PARTIAL OUTPUT: semua skenario gagal tidak boleh meninggalkan file
 *    parsial di destPath.
 * 5. WATERMARK FAIL-CLOSED (plan §5.4): dokumen tidak boleh keluar lewat
 *    retrieveStream() tanpa watermark — saat hook beforeStream gagal,
 *    sink WAJIB tetap 0 kali dipanggil.
 */
final class StorageSecurityTest extends TestCase
{
    private const KEK_ID = 'sectest';

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
        $this->envBackup['SECURE_KEKS'] = getenv('SECURE_KEKS');
        putenv('SECURE_KEKS=' . self::KEK_ID);
        $this->envBackup['SECURE_KEK_' . self::KEK_ID . '_B64'] = getenv('SECURE_KEK_' . self::KEK_ID . '_B64');
        putenv('SECURE_KEK_' . self::KEK_ID . '_B64=' . base64_encode(random_bytes(32)));
        $this->rootDir = sys_get_temp_dir() . '/sp_secstorage_' . bin2hex(random_bytes(6));
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

    private function storage(): SecureFileStorage
    {
        return new SecureFileStorage(LocalKms::fromEnv(), new LocalStorageAdapter($this->rootDir));
    }

    private function adapter(): LocalStorageAdapter
    {
        return new LocalStorageAdapter($this->rootDir);
    }

    private function storeSample(string $label): FileManifest
    {
        $src = sys_get_temp_dir() . '/sp_secsrc_' . bin2hex(random_bytes(6)) . '.bin';
        file_put_contents($src, random_bytes(150000)); // multi-frame @64KiB
        $this->tmpFiles[] = $src;
        $m = $this->storage()->store($src, ['client_id' => 'sec', 'kek_id' => self::KEK_ID, 'metadata' => ['label' => $label]]);
        return $m;
    }

    private function flipBlobByte(FileManifest $m, int $offset): string
    {
        $adapter = $this->adapter();
        $blob = $adapter->get($m->fileId());
        $this->assertLessThan(strlen($blob), $offset, 'Offset flip harus berada dalam batas blob.');
        $blob[$offset] = $blob[$offset] ^ "\x01";
        $adapter->put($m->fileId(), $blob);
        return $blob;
    }

    /**
     * Skenario umum: korupsi pada posisi tertentu → retrieve wajib gagal
     * dan tidak meninggalkan file parsial.
     */
    private function assertRetrieveFailsClosed(FileManifest $m, string $expectedMessagePart): void
    {
        $dest = sys_get_temp_dir() . '/sp_secdest_' . bin2hex(random_bytes(6)) . '.out';
        $this->tmpFiles[] = $dest;

        try {
            $this->storage()->retrieve($m, $dest);
            self::fail("Retrieve wajib gagal ($expectedMessagePart).");
        } catch (SecurePayloadException $e) {
            $this->assertStringContainsString($expectedMessagePart, $e->getMessage());
        }

        $this->assertFileDoesNotExist($dest, 'Tidak boleh ada file parsial di destPath.');
    }

    public function testBitflip_HeaderOffset0_RetrieveGagal(): void
    {
        $m = $this->storeSample('header-flip');
        $this->flipBlobByte($m, 0); // byte pertama secretstream header

        // Digest gate yang menangkap: pesan integritas digest.
        $this->assertRetrieveFailsClosed($m, 'cipher_digest tidak cocok');
    }

    public function testBitflip_TengahFrame_RetrieveGagal(): void
    {
        $m = $this->storeSample('mid-flip');
        $blobLen = strlen($this->adapter()->get($m->fileId()));
        // Offset tengah blob — gerbang digest menangkap apapun posisi bitflip
        // karena digest manifest tidak disesuaikan pada skenario ini.
        $this->flipBlobByte($m, intdiv($blobLen, 2));

        $this->assertRetrieveFailsClosed($m, 'cipher_digest tidak cocok');
    }

    public function testBitflip_ByteTerakhir_RetrieveGagal(): void
    {
        $m = $this->storeSample('tail-flip');
        $blobLen = strlen($this->adapter()->get($m->fileId()));
        $this->flipBlobByte($m, $blobLen - 1); // byte akhir tag auth frame FINAL

        $this->assertRetrieveFailsClosed($m, 'cipher_digest tidak cocok');
    }

    public function testBitflip_DigestDisesuaikanPenyerang_GagalDiAead(): void
    {
        $m = $this->storeSample('aead-flip');
        $tampered = $this->flipBlobByte($m, 24 + 4 + 5); // pasti di cipher frame pertama

        // Penyerang cerdas: perbarui digest manifest agar lolos gerbang digest.
        $data = $m->toArray();
        $data['cipher_digest'] = 'sha256=' . base64_encode(hash('sha256', $tampered, true));
        $evil = FileManifest::fromArray($data);

        // Gerbang kedua (AEAD secretstream auth tag) yang menolak → UNAUTHORIZED.
        $this->assertRetrieveFailsClosed($evil, 'Gagal mendekripsi chunk');
    }

    public function testSubstitusiWrappedDek_AntarDuaFile_UnwrapGagal(): void
    {
        $mA = $this->storeSample('file-a');
        $mB = $this->storeSample('file-b');

        // Ganti wrapped DEK milik B dengan milik A — AAD D4 mengikat file_id,
        // sehingga unwrap dengan aad_context B wajib gagal meski KEK sama.
        $data = $mB->toArray();
        $data['wrapped_dek_b64'] = $mA->wrappedDekB64();
        $swapped = FileManifest::fromArray($data);

        $this->assertRetrieveFailsClosed($swapped, 'Wrapped DEK tidak dapat dibuka');

        // Pastikan kode statusnya UNAUTHORIZED (bukan error lain).
        $dest = sys_get_temp_dir() . '/sp_secdest2_' . bin2hex(random_bytes(6)) . '.out';
        $this->tmpFiles[] = $dest;
        try {
            $this->storage()->retrieve($swapped, $dest);
            self::fail('Unwrap dengan wrapped DEK file lain wajib gagal.');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::UNAUTHORIZED, $e->getCode());
        }
        $this->assertFileDoesNotExist($dest);
    }

    public function testCipherDigestDimodifikasiDiManifest_Ditolak(): void
    {
        $m = $this->storeSample('digest-tamper');
        $data = $m->toArray();
        $data['cipher_digest'] = 'sha256=' . base64_encode(random_bytes(32));
        $evil = FileManifest::fromArray($data);

        // Pesan spesifik gerbang digest → verifikasi ditolak SEBELUM dekripsi.
        $this->assertRetrieveFailsClosed($evil, 'Integritas blob gagal');
    }

    public function testAadContextDimodifikasi_FileIdDiganti_UnwrapGagal(): void
    {
        $m = $this->storeSample('aad-tamper');
        $data = $m->toArray();
        /** @var array<string,string> $aad */
        $aad = $data['aad_context'];
        $aad['file_id'] = bin2hex(random_bytes(16)); // penyerang ubah binding file_id
        $data['aad_context'] = $aad;
        $evil = FileManifest::fromArray($data);

        $dest = sys_get_temp_dir() . '/sp_secdest3_' . bin2hex(random_bytes(6)) . '.out';
        $this->tmpFiles[] = $dest;

        try {
            $this->storage()->retrieve($evil, $dest);
            self::fail('Unwrap dengan aad_context yang dimodifikasi wajib gagal.');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::UNAUTHORIZED, $e->getCode(), 'Kegagalan harus dari gerbang unwrap (UNAUTHORIZED).');
        }
        $this->assertFileDoesNotExist($dest);
    }

    public function testWatermarkHookGagal_DokumenTidakKeluar_SinkNolKali(): void
    {
        $events = [];
        $storage = new SecureFileStorage(LocalKms::fromEnv(), new LocalStorageAdapter($this->rootDir), [
            'onSecurityEvent' => static function (string $event, array $ctx) use (&$events): void {
                $events[] = [$event, $ctx];
            },
        ]);
        $m = $this->storeSample('wm-fail');

        $sinkCalls = 0;
        try {
            $storage->retrieveStream(
                $m,
                static function (string $chunk) use (&$sinkCalls): void {
                    $sinkCalls++;
                    unset($chunk);
                },
                [
                    'beforeStream' => static function (string $plain): string {
                        unset($plain);
                        throw new \RuntimeException('mesin watermark down');
                    },
                ]
            );
            self::fail('Hook watermark gagal wajib menggagalkan streaming.');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::SERVER_ERROR, $e->getCode());
            $this->assertNotNull($e->getPrevious());
        }

        // INVARIANT: dokumen tidak boleh keluar tanpa watermark.
        $this->assertSame(0, $sinkCalls, 'Sink wajib 0 kali — NOL byte dokumen terkirim saat hook gagal.');

        $failed = array_values(array_filter($events, static fn (array $e): bool => $e[0] === 'file_watermark_failed'));
        $this->assertCount(1, $failed, 'Event file_watermark_failed wajib tercatat untuk audit.');
        $this->assertSame(['file_id' => $m->fileId()], $failed[0][1]);
    }
}
