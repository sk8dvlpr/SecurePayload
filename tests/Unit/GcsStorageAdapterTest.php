<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\Storage\Adapter\GcsStorageAdapter;

/**
 * Unit test GcsStorageAdapter memakai fake bucket duck-typed (tanpa SDK/jaringan):
 * CRUD, validasi argumen (name), fail-fast konstruktor, dan pembungkusan error.
 */
final class GcsStorageAdapterTest extends TestCase
{
    public function testPutGetRoundTripStoresIdenticalContents(): void
    {
        $fake = new FakeGcsBucket();
        $adapter = new GcsStorageAdapter($fake);
        $key = self::key();

        $adapter->put($key, 'isi-blob-rahasia');
        self::assertSame('isi-blob-rahasia', $adapter->get($key));
    }

    public function testExistsAndDeleteLifecycle(): void
    {
        $fake = new FakeGcsBucket();
        $adapter = new GcsStorageAdapter($fake);
        $key = self::key();

        self::assertFalse($adapter->exists($key));
        $adapter->put($key, 'x');
        self::assertTrue($adapter->exists($key));
        $adapter->delete($key);
        self::assertFalse($adapter->exists($key));
    }

    public function testOverwriteReplacesOldContent(): void
    {
        $adapter = new GcsStorageAdapter(new FakeGcsBucket());
        $key = self::key();

        $adapter->put($key, 'lama');
        $adapter->put($key, 'baru');
        self::assertSame('baru', $adapter->get($key));
    }

    public function testUploadReceivesNameArgument(): void
    {
        $fake = new FakeGcsBucket();
        $adapter = new GcsStorageAdapter($fake);
        $key = self::key();

        $adapter->put($key, 'v');

        self::assertCount(1, $fake->uploads);
        [$content, $opts] = $fake->uploads[0];
        self::assertSame('v', $content);
        self::assertSame($key, $opts['name'] ?? null);
    }

    public function testConstructorRejectsClientWithoutRequiredMethods(): void
    {
        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionCode(SecurePayloadException::BAD_REQUEST);
        $this->expectExceptionMessage('upload()');
        new GcsStorageAdapter(new \stdClass(), []);
    }

    /**
     * @dataProvider invalidKeyProvider
     */
    public function testInvalidKeysRejectedWithoutTouchingClient(string $key): void
    {
        $fake = new FakeGcsBucket();
        $adapter = new GcsStorageAdapter($fake);

        try {
            $adapter->get($key);
            self::fail('get harus menolak key invalid');
        } catch (SecurePayloadException $e) {
            self::assertSame(SecurePayloadException::BAD_REQUEST, $e->getCode());
        }
        self::assertSame(0, $fake->objectLookups, 'bucket tidak boleh terpanggil untuk key invalid');
    }

    /**
     * @return list<list<string>>
     */
    public static function invalidKeyProvider(): array
    {
        return [
            ['../../secret'],
            ['ABCDEF0123456789ABCDEF0123456789'], // uppercase
            ['abc123'],                            // terlalu pendek
            [''],
        ];
    }

    public function testSdkExceptionIsWrappedWithIndonesianMessageAndPrevious(): void
    {
        $fake = new class () {
            public function upload($data, array $options = []): void
            {
                unset($data, $options);
                throw new RuntimeException('boom dari gcs', 555);
            }
            public function object(string $name): object
            {
                unset($name);
                throw new RuntimeException('tidak seharusnya dipanggil');
            }
        };
        $adapter = new GcsStorageAdapter($fake);

        try {
            $adapter->put(self::key(), 'x');
            self::fail('harus melempar SecurePayloadException hasil bungkus');
        } catch (SecurePayloadException $e) {
            self::assertSame(SecurePayloadException::SERVER_ERROR, $e->getCode());
            self::assertStringContainsString('gagal menyimpan blob', $e->getMessage());
            self::assertStringContainsString('boom dari gcs', $e->getMessage());
            self::assertNotNull($e->getPrevious());
            self::assertSame(555, $e->getPrevious()->getCode());
        }
    }

    public function testGet_BlobKosong_DikembalikanApaAdanya(): void
    {
        // Semantik konsisten dengan Local/S3 (m3): isi blob dikembalikan apa adanya,
        // termasuk string kosong — tanpa penolakan khusus.
        $fake = new FakeGcsBucket();
        $key = self::key();
        $fake->upload('', ['name' => $key]);
        $adapter = new GcsStorageAdapter($fake);
        self::assertSame('', $adapter->get($key));
    }

    private static function key(): string
    {
        return bin2hex(random_bytes(16));
    }
}

/**
 * Fake Google\Cloud\Storage\Bucket minimal untuk pengujian duck-typing.
 * Method internal_* dipakai FakeGcsObject untuk mengakses state bucket.
 */
final class FakeGcsBucket
{
    /** @var list<array{string, array<string,mixed>}> */
    public array $uploads = [];

    /** @var int Jumlah pemanggilan object() (untuk assert tidak tersentuh). */
    public int $objectLookups = 0;

    /** @var array<string,string> */
    private array $objects = [];

    /**
     * @param mixed $data
     * @param array<string,mixed> $options
     */
    public function upload($data, array $options = []): FakeGcsObject
    {
        $name = (string) ($options['name'] ?? '');
        if ($name === '') {
            throw new RuntimeException('nama object wajib diisi');
        }
        $this->uploads[] = [(string) $data, $options];
        $this->objects[$name] = (string) $data;
        return new FakeGcsObject($this, $name);
    }

    public function object(string $name): FakeGcsObject
    {
        $this->objectLookups++;
        return new FakeGcsObject($this, $name);
    }

    // --- helper dipanggil lewat FakeGcsObject ---

    public function downloadByName(string $name): string
    {
        return $this->objects[$name] ?? '';
    }

    public function hasObject(string $name): bool
    {
        return isset($this->objects[$name]);
    }

    public function removeByName(string $name): void
    {
        unset($this->objects[$name]);
    }
}

/**
 * Fake Google\Cloud\Storage\StorageObject minimal.
 */
final class FakeGcsObject
{
    private FakeGcsBucket $bucket;

    private string $name;

    public function __construct(FakeGcsBucket $bucket, string $name)
    {
        $this->bucket = $bucket;
        $this->name = $name;
    }

    public function downloadAsString(): string
    {
        return $this->bucket->downloadByName($this->name);
    }

    public function exists(): bool
    {
        return $this->bucket->hasObject($this->name);
    }

    public function delete(): void
    {
        $this->bucket->removeByName($this->name);
    }
}
