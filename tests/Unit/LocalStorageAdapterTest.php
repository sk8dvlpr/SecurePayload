<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\Storage\Adapter\LocalStorageAdapter;

/**
 * Unit test LocalStorageAdapter: CRUD, validasi key fail-closed,
 * dan penulisan atomik.
 */
final class LocalStorageAdapterTest extends TestCase
{
    private string $rootDir;

    private LocalStorageAdapter $adapter;

    protected function setUp(): void
    {
        $this->rootDir = sys_get_temp_dir() . '/sp_store_test_' . bin2hex(random_bytes(6));
        $this->adapter = new LocalStorageAdapter($this->rootDir);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->rootDir);
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
            if (is_dir($path)) {
                $this->removeDir($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }

    private function validKey(): string
    {
        return bin2hex(random_bytes(16));
    }

    public function testPutGetDeleteExists_HappyPath(): void
    {
        $key = $this->validKey();
        $this->assertFalse($this->adapter->exists($key));

        $this->adapter->put($key, 'isi-blob');
        $this->assertTrue($this->adapter->exists($key));
        $this->assertSame('isi-blob', $this->adapter->get($key));

        $this->adapter->delete($key);
        $this->assertFalse($this->adapter->exists($key));
    }

    public function testPutOverwrite_MenghasilkanKontenBaru(): void
    {
        $key = $this->validKey();
        $this->adapter->put($key, 'versi-lama');
        // Tulis ulang (atomik: tmp + rename) harus menimpa seluruh isi.
        $this->adapter->put($key, str_repeat('B', 100000));
        $this->assertSame(str_repeat('B', 100000), $this->adapter->get($key));
        $this->assertStringNotContainsString('versi-lama', $this->adapter->get($key));

        // Tidak ada file sementara yang tertinggal di direktori.
        $leftovers = array_filter(scandir($this->rootDir) ?: [], static fn (string $f): bool => str_contains($f, '.tmp-'));
        $this->assertSame([], array_values($leftovers), 'File tmp tidak boleh tertinggal setelah put.');
    }

    public function testPutBinaryContent_RoundTripIdentik(): void
    {
        $key = $this->validKey();
        $binary = random_bytes(70000); // > satu chunk baca biasa
        $this->adapter->put($key, $binary);
        $this->assertTrue(hash_equals($binary, $this->adapter->get($key)));
    }

    public function testDelete_KeySudahTidakAda_NoOp(): void
    {
        $key = $this->validKey();
        $this->adapter->put($key, 'x');
        $this->adapter->delete($key);
        // Delete kedua pada key yang sudah hilang = no-op (idempoten).
        $this->adapter->delete($key);
        $this->assertFalse($this->adapter->exists($key));
    }

    /**
     * @return list<array{string}> Key tidak valid (path traversal/format salah).
     */
    public function providerInvalidKeys(): array
    {
        return [
            ['../etc/passwd'],
            [strtoupper(str_repeat('ab', 16))],   // uppercase ditolak
            [str_repeat('a', 31)],                // kurang 1 char
            ['../../' . str_repeat('a', 32)],
            ['a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p'],  // mengandung slash
            [''],
        ];
    }

    /** @dataProvider providerInvalidKeys */
    public function testKeyInvalid_Put_Throw(string $key): void
    {
        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionCode(SecurePayloadException::BAD_REQUEST);
        $this->adapter->put($key, 'data');
    }

    /** @dataProvider providerInvalidKeys */
    public function testKeyInvalid_Get_Throw(string $key): void
    {
        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionCode(SecurePayloadException::BAD_REQUEST);
        $this->adapter->get($key);
    }

    /** @dataProvider providerInvalidKeys */
    public function testKeyInvalid_Delete_Throw(string $key): void
    {
        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionCode(SecurePayloadException::BAD_REQUEST);
        $this->adapter->delete($key);
    }

    /** @dataProvider providerInvalidKeys */
    public function testKeyInvalid_Exists_Throw(string $key): void
    {
        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionCode(SecurePayloadException::BAD_REQUEST);
        $this->adapter->exists($key);
    }

    public function testGet_KeyTidakAda_Throw(): void
    {
        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionMessage('Blob tidak ditemukan');
        $this->adapter->get($this->validKey());
    }

    public function testConstructor_MembuatDirektoriRekursif_DenganMode(): void
    {
        $nested = sys_get_temp_dir() . '/sp_store_nested_' . bin2hex(random_bytes(4)) . '/a/b';
        try {
            $adapter = new LocalStorageAdapter($nested, ['dirMode' => 0770]);
            $this->assertDirectoryExists($nested);
            $key = bin2hex(random_bytes(16));
            $adapter->put($key, 'ok');
            $this->assertSame('ok', $adapter->get($key));
        } finally {
            $this->removeDir(dirname($nested));
        }
    }

    /** @dataProvider providerInvalidModes */
    public function testConstructor_FileModeInvalid_Throw($mode): void
    {
        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionCode(SecurePayloadException::BAD_REQUEST);
        new LocalStorageAdapter($this->rootDir, ['fileMode' => $mode]);
    }

    /**
     * @return list<list<mixed>>
     */
    public function providerInvalidModes(): array
    {
        return [
            ['0660'],   // string, bukan int
            [0],        // nol
            [-1],       // negatif
            [1.5],      // float
        ];
    }

    public function testPut_DenganFileModeCustom_RoundTripTetapJalan(): void
    {
        // Perilaku fungsional: chmod gagal di filesystem tanpa dukungan TIDAK boleh
        // menggagalkan put() — round-trip harus tetap sukses. Asersi mode bit sengaja
        // tidak dibuat karena fileperms() tidak portable (Windows).
        $adapter = new LocalStorageAdapter($this->rootDir, ['fileMode' => 0600]);
        $key = $this->validKey();
        $adapter->put($key, 'isi-rahasia');
        $this->assertSame('isi-rahasia', $adapter->get($key));
    }
}
