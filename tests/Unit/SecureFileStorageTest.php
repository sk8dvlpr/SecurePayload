<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\KMS\LocalKms;
use SecurePayload\Storage\Adapter\LocalStorageAdapter;
use SecurePayload\Storage\FileManifest;
use SecurePayload\Storage\SecureFileStorage;
use SecurePayload\SecurePayload;

/**
 * Unit test SecureFileStorage: round-trip store/retrieve/stream/delete
 * memakai LocalKms (env) + LocalStorageAdapter (temp dir).
 */
final class SecureFileStorageTest extends TestCase
{
    private const KEK_ID = 'test';

    /** @var array<string,string|false> */
    private array $envBackup = [];

    private string $rootDir;

    protected function setUp(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium diperlukan untuk storage terenkripsi');
        }
        $this->envBackup = [];
        // Pola backup/restore env seperti LocalKmsTest.
        $this->setEnv('SECURE_KEKS', self::KEK_ID);
        $this->setEnv('SECURE_KEK_' . self::KEK_ID . '_B64', base64_encode(random_bytes(32)));
        $this->rootDir = sys_get_temp_dir() . '/sp_storage_test_' . bin2hex(random_bytes(6));
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
        $this->removeDir($this->rootDir);
    }

    /**
     * @param array<string,mixed> $opts
     */
    private function storage(array $opts = []): SecureFileStorage
    {
        return new SecureFileStorage(LocalKms::fromEnv(), new LocalStorageAdapter($this->rootDir), $opts);
    }

    private function setEnv(string $key, string $value): void
    {
        $this->envBackup[$key] = getenv($key);
        putenv("$key=$value");
    }

    private function srcFile(string $content): string
    {
        $p = sys_get_temp_dir() . '/sp_src_' . bin2hex(random_bytes(6)) . '.bin';
        if (file_put_contents($p, $content) === false) {
            self::fail("Gagal menulis file sumber uji: $p");
        }
        return $p;
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

    public function testStoreRetrieve_RoundTrip_ByteIdentik(): void
    {
        $storage = $this->storage();
        $content = random_bytes(150000); // multi-chunk @ 64KiB
        $src = $this->srcFile($content);

        $m = $storage->store($src, ['client_id' => 'c1', 'kek_id' => self::KEK_ID]);

        $this->assertSame(SecurePayload::STREAM_ALG, $m->alg());
        $this->assertSame(self::KEK_ID, $m->kekId());
        $this->assertSame(strlen($content), $m->size());
        $this->assertMatchesRegularExpression('/^[a-f0-9]{32}$/', $m->fileId());

        $dest = $src . '.out';
        $res = $storage->retrieve($m, $dest);
        $this->assertSame($dest, $res['path']);
        $this->assertSame(strlen($content), $res['size']);
        $this->assertTrue(hash_equals($content, (string) file_get_contents($dest)), 'Plaintext hasil retrieve harus identik byte-per-byte.');

        @unlink($dest);
        @unlink($src);
    }

    public function testRetrieveStream_ConcatChunk_EqualsOriginal(): void
    {
        $storage = $this->storage();
        $content = random_bytes(200000); // > 3 chunk sink 64KB
        $src = $this->srcFile($content);
        $m = $storage->store($src, ['client_id' => 'c1', 'kek_id' => self::KEK_ID]);

        $buf = '';
        $chunks = 0;
        $storage->retrieveStream($m, static function (string $chunk) use (&$buf, &$chunks): void {
            $buf .= $chunk;
            $chunks++;
        });

        $this->assertTrue(hash_equals($content, $buf), 'Gabungan chunk stream harus identik dengan original.');
        $this->assertGreaterThanOrEqual(3, $chunks, 'File 200KB harus terkirim lebih dari satu chunk 64KB.');

        @unlink($src);
    }

    public function testRetrieveStream_TanpaBeforeStream_ByteIdentikRegresi(): void
    {
        $storage = $this->storage();
        $content = random_bytes(150000);
        $src = $this->srcFile($content);
        $m = $storage->store($src, ['client_id' => 'c1', 'kek_id' => self::KEK_ID]);

        // Panggilan lama 2-argumen tetap berperilaku persis sama.
        $buf2 = '';
        $chunks2 = 0;
        $storage->retrieveStream($m, static function (string $chunk) use (&$buf2, &$chunks2): void {
            $buf2 .= $chunk;
            $chunks2++;
        });

        // Panggilan baru 3-argumen dengan opts kosong harus identik.
        $buf3 = '';
        $chunks3 = 0;
        $storage->retrieveStream($m, static function (string $chunk) use (&$buf3, &$chunks3): void {
            $buf3 .= $chunk;
            $chunks3++;
        }, []);

        $this->assertTrue(hash_equals($content, $buf2), 'Panggilan 2-argumen (kompatibilitas lama) tetap byte-identik.');
        $this->assertSame($chunks2, $chunks3, 'opts kosong tidak boleh mengubah pembagian chunk.');
        $this->assertTrue(hash_equals($buf2, $buf3), 'Output 3-argumen dengan opts kosong harus identik dengan 2-argumen.');

        @unlink($src);
    }

    public function testRetrieveStream_HookTransformasi_OutputTerwatermark_UrutanHookSebelumSink(): void
    {
        $storage = $this->storage();
        $content = random_bytes(200000); // multi-chunk @ sink 64KB
        $src = $this->srcFile($content);
        $m = $storage->store($src, ['client_id' => 'c1', 'kek_id' => self::KEK_ID]);

        /** @var list<string> $log Urutan operasi: 'hook' dan 'sink'. */
        $log = [];
        $buf = '';
        $storage->retrieveStream(
            $m,
            static function (string $chunk) use (&$buf, &$log): void {
                $log[] = 'sink';
                $buf .= $chunk;
            },
            [
                'beforeStream' => static function (string $plain) use (&$log): string {
                    $log[] = 'hook';
                    return $plain . "\n--WATERMARK:uji--";
                },
            ]
        );

        $this->assertSame(['hook', 'sink'], array_unique($log), 'Hook wajib dipanggil tepat 1x SEBELUM sink pertama.');
        $this->assertSame('hook', $log[0], 'Operasi pertama harus hook watermark.');
        $this->assertTrue(
            hash_equals($content . "\n--WATERMARK:uji--", $buf),
            'Gabungan seluruh chunk harus sama dengan plaintext terwatermark.'
        );

        @unlink($src);
    }

    public function testRetrieveStream_HookMenerimaPlaintextPenuh_FileIdDanRequesterUtuh(): void
    {
        $storage = $this->storage();
        $content = random_bytes(70000);
        $src = $this->srcFile($content);
        $m = $storage->store($src, ['client_id' => 'c1', 'kek_id' => self::KEK_ID]);

        $requester = ['user_id' => 'u-42', 'unit' => 'audit'];
        /** @var array{len:int,file_id:?string,requester:mixed}|null $captured */
        $captured = null;
        $storage->retrieveStream(
            $m,
            static function (string $chunk): void {
                unset($chunk);
            },
            [
                'requester' => $requester,
                'beforeStream' => static function (string $plain, FileManifest $mm, array $ctx) use (&$captured): string {
                    $captured = [
                        'len' => strlen($plain),
                        'file_id' => $ctx['file_id'] ?? null,
                        'requester' => $ctx['requester'] ?? null,
                    ];
                    return $plain;
                },
            ]
        );

        $this->assertNotNull($captured);
        $this->assertSame(strlen($content), $captured['len'], 'Hook menerima plaintext PENUH (strlen == ukuran manifest).');
        $this->assertSame($m->size(), $captured['len']);
        $this->assertSame($m->fileId(), $captured['file_id']);
        $this->assertSame($requester, $captured['requester'], 'Requester wajib diteruskan utuh ke hook.');

        @unlink($src);
    }

    public function testRetrieveStream_ReturnBukanString_BadRequestTanpaSink(): void
    {
        $storage = $this->storage();
        $src = $this->srcFile('data uji');
        $m = $storage->store($src, ['client_id' => 'c1', 'kek_id' => self::KEK_ID]);

        $sinkCalls = 0;
        foreach ([123, null, ['bukan' => 'string']] as $returnNilai) {
            try {
                $storage->retrieveStream(
                    $m,
                    static function (string $chunk) use (&$sinkCalls): void {
                        $sinkCalls++;
                    },
                    [
                        'beforeStream' => static function (string $plain) use ($returnNilai) {
                            unset($plain);
                            return $returnNilai;
                        },
                    ]
                );
                self::fail('Return hook bukan string wajib ditolak BAD_REQUEST.');
            } catch (SecurePayloadException $e) {
                $this->assertSame(SecurePayloadException::BAD_REQUEST, $e->getCode());
            }
        }
        $this->assertSame(0, $sinkCalls, 'Return tidak valid wajib menggagalkan stream sebelum sink apa pun.');

        @unlink($src);
    }

    public function testRetrieveStream_BeforeStreamBukanCallable_BadRequest(): void
    {
        $storage = $this->storage();
        $src = $this->srcFile('data uji');
        $m = $storage->store($src, ['client_id' => 'c1', 'kek_id' => self::KEK_ID]);

        try {
            $storage->retrieveStream($m, static function (string $chunk): void {
                unset($chunk);
            }, ['beforeStream' => 'bukan-callable']);
            self::fail('beforeStream non-callable wajib ditolak BAD_REQUEST.');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::BAD_REQUEST, $e->getCode());
            $this->assertStringContainsString('callable', $e->getMessage());
        }

        @unlink($src);
    }

    public function testRetrieveStream_HookThrow_PropagasiFailClosedDanEventGagal(): void
    {
        $events = [];
        $storage = $this->storage([
            'onSecurityEvent' => static function (string $event, array $ctx) use (&$events): void {
                $events[] = [$event, $ctx];
            },
        ]);
        $content = random_bytes(150000);
        $src = $this->srcFile($content);
        $m = $storage->store($src, ['client_id' => 'c1', 'kek_id' => self::KEK_ID]);

        $sinkCalls = 0;
        try {
            $storage->retrieveStream(
                $m,
                static function (string $chunk) use (&$sinkCalls): void {
                    $sinkCalls++;
                },
                [
                    'beforeStream' => static function (string $plain): string {
                        unset($plain);
                        throw new \RuntimeException('mesin watermark mati');
                    },
                ]
            );
            self::fail('Exception hook wajib dipropagasi.');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::SERVER_ERROR, $e->getCode());
            $this->assertNotNull($e->getPrevious(), 'Exception penyebab wajib ter-chain sebagai previous.');
            $this->assertInstanceOf(\RuntimeException::class, $e->getPrevious());
            $this->assertStringContainsString('Watermark forensik gagal', $e->getMessage());
        }

        $this->assertSame(0, $sinkCalls, 'FAIL-CLOSED: kegagalan hook menjamin NOL byte body terkirim.');
        $failed = array_values(array_filter($events, static fn (array $e): bool => $e[0] === SecurePayload::EVENT_FILE_WATERMARK_FAILED));
        $this->assertCount(1, $failed, 'Event file_watermark_failed wajib tercatat tepat sekali.');
        $this->assertSame(['file_id' => $m->fileId()], $failed[0][1], 'Konteks event gagal hanya file_id (non-secret).');

        @unlink($src);
    }

    public function testRetrieveStream_PlaintextKosong_HookTetapDipanggil_TanpaChunk(): void
    {
        $storage = $this->storage();
        $src = $this->srcFile('');
        $m = $storage->store($src, ['client_id' => 'c1', 'kek_id' => self::KEK_ID]);
        $this->assertSame(0, $m->size());

        $hookCalls = 0;
        /** @var list<string> $plainDiterima */
        $plainDiterima = [];
        $sinkCalls = 0;
        $storage->retrieveStream(
            $m,
            static function (string $chunk) use (&$sinkCalls): void {
                $sinkCalls++;
                unset($chunk);
            },
            [
                'beforeStream' => static function (string $plain) use (&$hookCalls, &$plainDiterima): string {
                    $hookCalls++;
                    $plainDiterima[] = $plain;
                    return '';
                },
            ]
        );

        $this->assertSame([''], $plainDiterima, 'Plaintext kosong tetap kontrak seragam untuk hook.');
        $this->assertSame(1, $hookCalls, 'Plaintext kosong: hook TETAP dipanggil (kontrak seragam).');
        $this->assertSame(0, $sinkCalls, 'Plaintext kosong: loop str_split dilewati, tanpa chunk ke sink.');

        @unlink($src);
    }

    public function testRetrieveStream_Sukses_EventWatermarkedTercatat(): void
    {
        $events = [];
        $storage = $this->storage([
            'onSecurityEvent' => static function (string $event, array $ctx) use (&$events): void {
                $events[] = [$event, $ctx];
            },
        ]);
        $src = $this->srcFile('dokumen rahasia');
        $m = $storage->store($src, ['client_id' => 'c1', 'kek_id' => self::KEK_ID]);

        $storage->retrieveStream(
            $m,
            static function (string $chunk): void {
                unset($chunk);
            },
            [
                'beforeStream' => static fn (string $plain): string => '[WM] ' . $plain,
            ]
        );

        $ok = array_values(array_filter($events, static fn (array $e): bool => $e[0] === SecurePayload::EVENT_FILE_WATERMARKED));
        $this->assertCount(1, $ok, 'Event file_watermarked wajib tercatat tepat sekali saat hook sukses.');
        $this->assertSame(['file_id' => $m->fileId()], $ok[0][1], 'Konteks event sukses hanya file_id (non-secret).');

        @unlink($src);
    }

    public function testMetadata_TersimpanDiManifest(): void
    {
        $storage = $this->storage();
        $src = $this->srcFile('data kecil');
        $m = $storage->store($src, [
            'client_id' => 'c1',
            'kek_id' => self::KEK_ID,
            'purpose' => 'backup',
            'metadata' => ['name' => 'laporan.pdf', 'owner' => 'finance'],
        ]);

        $this->assertSame(['name' => 'laporan.pdf', 'owner' => 'finance'], $m->metadata());

        @unlink($src);
    }

    public function testDuaStore_FileIdUnik(): void
    {
        $storage = $this->storage();
        $src = $this->srcFile('sama');

        $m1 = $storage->store($src, ['client_id' => 'c1', 'kek_id' => self::KEK_ID]);
        $m2 = $storage->store($src, ['client_id' => 'c1', 'kek_id' => self::KEK_ID]);

        $this->assertNotSame($m1->fileId(), $m2->fileId(), 'file_id harus unik antar store (random 128-bit).');
        $this->assertTrue($storage->exists($m1));
        $this->assertTrue($storage->exists($m2));

        @unlink($src);
    }

    public function testDelete_ExistsFalse_RetrieveThrow(): void
    {
        $storage = $this->storage();
        $src = $this->srcFile('akan dihapus');
        $m = $storage->store($src, ['client_id' => 'c1', 'kek_id' => self::KEK_ID]);
        $this->assertTrue($storage->exists($m));

        $storage->delete($m);
        $this->assertFalse($storage->exists($m), 'Blob harus hilang setelah delete.');

        $this->expectException(SecurePayloadException::class);
        $storage->retrieve($m, $src . '.out');
    }

    public function testManifestRoundTripViaArray_RetrieveTetapJalan(): void
    {
        $storage = $this->storage();
        $content = random_bytes(70000);
        $src = $this->srcFile($content);
        $m = $storage->store($src, ['client_id' => 'c1', 'kek_id' => self::KEK_ID]);

        // Simulasi persist ke DB aplikasi: JSON encode/decode lalu fromArray ulang.
        $json = json_encode($m->toArray());
        $this->assertIsString($json);
        /** @var array<string,mixed> $restored */
        $restored = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        $m2 = FileManifest::fromArray($restored);

        $dest = $src . '.out';
        $res = $storage->retrieve($m2, $dest);
        $this->assertSame(strlen($content), $res['size']);
        $this->assertTrue(hash_equals($content, (string) file_get_contents($dest)));

        @unlink($dest);
        @unlink($src);
    }

    public function testStore_FileKosong_RoundTripOk(): void
    {
        $storage = $this->storage();
        $src = $this->srcFile('');
        $m = $storage->store($src, ['client_id' => 'c1', 'kek_id' => self::KEK_ID]);
        $this->assertSame(0, $m->size());

        $dest = $src . '.out';
        $res = $storage->retrieve($m, $dest);
        $this->assertSame('', (string) file_get_contents($dest));
        $this->assertSame(0, $res['size']);

        @unlink($dest);
        @unlink($src);
    }

    public function testRetrieve_ManifestVersiAtauAlgTidakDidukung_DitolakFailClosed(): void
    {
        $storage = $this->storage();
        $src = $this->srcFile('data uji');
        $m = $storage->store($src, ['client_id' => 'c1', 'kek_id' => self::KEK_ID]);

        // Manifest valid → override field v menjadi versi tak dikenal ('9').
        /** @var array<string,mixed> $data */
        $data = $m->toArray();
        $data['v'] = '9';
        $mV9 = FileManifest::fromArray($data);

        try {
            $storage->retrieve($mV9, $src . '.out');
            self::fail('retrieve harus menolak manifest versi format tak dikenal');
        } catch (SecurePayloadException $e) {
            self::assertSame(SecurePayloadException::UNPROCESSABLE, $e->getCode());
            self::assertStringContainsString('tidak didukung', $e->getMessage());
        }

        // Override alg menjadi algoritma lain → juga ditolak.
        /** @var array<string,mixed> $data2 */
        $data2 = $m->toArray();
        $data2['alg'] = 'xchacha20poly1305-lain';
        $mAlg = FileManifest::fromArray($data2);

        try {
            $storage->retrieveStream($mAlg, static function (string $chunk): void {
                unset($chunk);
            });
            self::fail('retrieveStream harus menolak manifest algoritma tak cocok');
        } catch (SecurePayloadException $e) {
            self::assertSame(SecurePayloadException::UNPROCESSABLE, $e->getCode());
            self::assertStringContainsString('tidak cocok', $e->getMessage());
        }

        @unlink($src);
    }

    public function testEventEmitted_SaatStoreDanDelete(): void
    {
        $events = [];
        $storage = $this->storage([
            'onSecurityEvent' => static function (string $event, array $ctx) use (&$events): void {
                $events[] = [$event, $ctx];
            },
        ]);
        $src = $this->srcFile('abc');
        $m = $storage->store($src, ['client_id' => 'c9', 'kek_id' => self::KEK_ID, 'purpose' => 'uji']);

        $this->assertCount(1, $events);
        $this->assertSame(SecurePayload::EVENT_FILE_STORED, $events[0][0]);
        $this->assertSame($m->fileId(), $events[0][1]['file_id'] ?? null);
        $this->assertSame(3, $events[0][1]['size'] ?? -1);

        $storage->delete($m);
        $this->assertCount(2, $events);
        $this->assertSame(SecurePayload::EVENT_FILE_DELETED, $events[1][0]);
        $this->assertSame($m->fileId(), $events[1][1]['file_id'] ?? null);

        @unlink($src);
    }

    public function testClockInjection_MengaturCreatedAt(): void
    {
        $storage = $this->storage(['clock' => static fn (): int => 1234567890]);
        $src = $this->srcFile('x');
        $m = $storage->store($src, ['client_id' => 'c1', 'kek_id' => self::KEK_ID]);
        $this->assertSame(1234567890, $m->createdAt());

        @unlink($src);
    }

    public function testChunkSizeDiLuarRentang_Throw(): void
    {
        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionCode(SecurePayloadException::BAD_REQUEST);
        $this->storage(['chunkSize' => 512]); // < 1KiB
    }

    public function testChunkSizeCustom_DipakaiDanTercatatDiManifest(): void
    {
        $storage = $this->storage(['chunkSize' => 1024]);
        $src = $this->srcFile(str_repeat('z', 3000)); // 3 frame @ 1KiB
        $m = $storage->store($src, ['client_id' => 'c1', 'kek_id' => self::KEK_ID]);
        $this->assertSame(1024, $m->chunkSize());

        $dest = $src . '.out';
        $storage->retrieve($m, $dest);
        $this->assertTrue(hash_equals(str_repeat('z', 3000), (string) file_get_contents($dest)));

        @unlink($dest);
        @unlink($src);
    }

    public function testStore_SumberTidakAda_Throw(): void
    {
        $storage = $this->storage();
        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionCode(SecurePayloadException::BAD_REQUEST);
        $storage->store(sys_get_temp_dir() . '/sp_tidak_ada_' . bin2hex(random_bytes(6)) . '.bin', ['client_id' => 'c1', 'kek_id' => self::KEK_ID]);
    }

    public function testStore_MetaTanpaClientId_Throw(): void
    {
        $storage = $this->storage();
        $src = $this->srcFile('x');
        try {
            $this->expectException(SecurePayloadException::class);
            $this->expectExceptionCode(SecurePayloadException::BAD_REQUEST);
            $storage->store($src, ['kek_id' => self::KEK_ID]);
        } finally {
            @unlink($src);
        }
    }
}
