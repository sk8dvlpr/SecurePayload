<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\Storage\Adapter\S3StorageAdapter;

/**
 * Unit test S3StorageAdapter memakai fake klien duck-typed (tanpa SDK/jaringan):
 * CRUD, validasi argumen (Bucket/Key), fail-fast konstruktor, dan pembungkusan error.
 */
final class S3StorageAdapterTest extends TestCase
{
    public function testPutGetRoundTripStoresIdenticalContents(): void
    {
        $fake = new FakeS3Client();
        $adapter = new S3StorageAdapter($fake, ['bucket' => 'bkt']);
        $key = self::key();

        $adapter->put($key, 'isi-blob-rahasia');
        self::assertSame('isi-blob-rahasia', $adapter->get($key));
    }

    public function testExistsAndDeleteLifecycle(): void
    {
        $fake = new FakeS3Client();
        $adapter = new S3StorageAdapter($fake, ['bucket' => 'bkt']);
        $key = self::key();

        self::assertFalse($adapter->exists($key));
        $adapter->put($key, 'x');
        self::assertTrue($adapter->exists($key));
        $adapter->delete($key);
        self::assertFalse($adapter->exists($key));
    }

    public function testOverwriteReplacesOldContent(): void
    {
        $adapter = new S3StorageAdapter(new FakeS3Client(), ['bucket' => 'bkt']);
        $key = self::key();

        $adapter->put($key, 'lama');
        $adapter->put($key, 'baru');
        self::assertSame('baru', $adapter->get($key));
    }

    public function testClientArgumentsContainBucketAndKey(): void
    {
        $fake = new FakeS3Client();
        $adapter = new S3StorageAdapter($fake, ['bucket' => 'my-bucket']);
        $key = self::key();

        $adapter->put($key, 'v');
        $adapter->get($key);
        $adapter->exists($key);
        $adapter->delete($key);

        foreach ($fake->calls as [$method, $args]) {
            self::assertSame('my-bucket', $args['Bucket'] ?? null, "argumen Bucket salah pada $method");
            self::assertSame($key, $args['Key'] ?? null, "argumen Key salah pada $method");
        }
        self::assertCount(4, $fake->calls);
    }

    public function testConstructorRejectsClientWithoutRequiredMethods(): void
    {
        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionCode(SecurePayloadException::BAD_REQUEST);
        $this->expectExceptionMessage('putObject');
        new S3StorageAdapter(new \stdClass(), ['bucket' => 'bkt']);
    }

    public function testConstructorRejectsEmptyBucket(): void
    {
        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionMessage('bucket');
        new S3StorageAdapter(new FakeS3Client(), ['bucket' => '   ']);
    }

    /**
     * @dataProvider invalidKeyProvider
     */
    public function testInvalidKeysRejectedWithoutTouchingClient(string $key): void
    {
        $fake = new FakeS3Client();
        $adapter = new S3StorageAdapter($fake, ['bucket' => 'bkt']);

        try {
            $adapter->put($key, 'x');
            self::fail('put harus menolak key invalid');
        } catch (SecurePayloadException $e) {
            self::assertSame(SecurePayloadException::BAD_REQUEST, $e->getCode());
        }
        self::assertCount(0, $fake->calls, 'client tidak boleh terpanggil untuk key invalid');
    }

    /**
     * @return list<list<string>>
     */
    public static function invalidKeyProvider(): array
    {
        return [
            ['../etc/passwd'],
            ['ABCDEF0123456789ABCDEF0123456789'], // uppercase
            ['abc123'],                            // terlalu pendek
            ['g1234567890123456789012345678901z'], // bukan hex
            [''],
        ];
    }

    public function testSdkExceptionIsWrappedWithIndonesianMessageAndPrevious(): void
    {
        $fake = new class () extends FakeS3Client {
            public function putObject(array $args): void
            {
                unset($args);
                throw new RuntimeException('boom dari sdk', 777);
            }
        };
        $adapter = new S3StorageAdapter($fake, ['bucket' => 'bkt']);

        try {
            $adapter->put(self::key(), 'x');
            self::fail('harus melempar SecurePayloadException hasil bungkus');
        } catch (SecurePayloadException $e) {
            self::assertSame(SecurePayloadException::SERVER_ERROR, $e->getCode());
            self::assertStringContainsString('gagal menyimpan blob', $e->getMessage());
            self::assertStringContainsString('boom dari sdk', $e->getMessage());
            self::assertNotNull($e->getPrevious());
            self::assertSame(777, $e->getPrevious()->getCode());
        }
    }

    public function testExists_PesanUmumBerisiNotFound_TidakDianggap404(): void
    {
        // Ketat (m8): substring "not found" pada ISI PESAN saja tidak boleh
        // dipetakan sebagai 404 — error generik tetap dilempar (fail-closed),
        // bukan dilaporkan sebagai "blob tidak ada".
        $fake = new class () extends FakeS3Client {
            public function headObject(array $args): array
            {
                unset($args);
                throw new RuntimeException('koneksi terputus: resource pool not found di konfigurasi');
            }
        };
        $adapter = new S3StorageAdapter($fake, ['bucket' => 'bkt']);

        try {
            $adapter->exists(self::key());
            self::fail('error non-404 tidak boleh dianggap object tidak ada');
        } catch (SecurePayloadException $e) {
            self::assertSame(SecurePayloadException::SERVER_ERROR, $e->getCode());
            self::assertStringContainsString('gagal memeriksa keberadaan blob', $e->getMessage());
        }
    }

    public function testExists_Error404ViaStatusCode_DiAnggapTidakAda(): void
    {
        // Bentuk realistis AWS SDK: S3Exception dengan getStatusCode() === 404.
        $fake = new class () extends FakeS3Client {
            public function headObject(array $args): array
            {
                unset($args);
                throw new FakeS3Status404();
            }
        };
        $adapter = new S3StorageAdapter($fake, ['bucket' => 'bkt']);
        self::assertFalse($adapter->exists(self::key()));
    }

    public function testGetObjectBodySupportsStreamLikeObject(): void
    {
        $fake = new class () extends FakeS3Client {
            public function getObject(array $args): array
            {
                $this->calls[] = ['getObject', $args];
                return ['Body' => new FakeStream('stream-content')];
            }
        };
        $adapter = new S3StorageAdapter($fake, ['bucket' => 'bkt']);
        self::assertSame('stream-content', $adapter->get(self::key()));
    }

    private static function key(): string
    {
        return bin2hex(random_bytes(16));
    }
}

/**
 * Fake Aws\S3\S3Client minimal untuk pengujian duck-typing.
 * Tidak final agar bisa dioverride anonymous class di test.
 */
class FakeS3Client
{
    /** @var list<array{string, array<string,mixed>}> */
    public array $calls = [];

    /** @var array<string,string> */
    private array $objects = [];

    public function putObject(array $args): void
    {
        $this->calls[] = ['putObject', $args];
        $this->objects[$args['Key']] = (string) $args['Body'];
    }

    public function getObject(array $args): array
    {
        $this->calls[] = ['getObject', $args];
        if (!isset($this->objects[$args['Key']])) {
            throw new FakeS3NoSuchKey('NoSuchKey: ' . $args['Key']);
        }
        return ['Body' => $this->objects[$args['Key']]];
    }

    public function headObject(array $args): array
    {
        $this->calls[] = ['headObject', $args];
        if (!isset($this->objects[$args['Key']])) {
            throw new FakeS3NotFound('NotFound: ' . $args['Key']);
        }
        return ['ContentLength' => strlen($this->objects[$args['Key']])];
    }

    public function deleteObject(array $args): void
    {
        $this->calls[] = ['deleteObject', $args];
        unset($this->objects[$args['Key']]);
    }
}

/**
 * Fake error "object tidak ada" ala Aws\S3\Exception\S3Exception (NoSuchKey).
 */
final class FakeS3NoSuchKey extends RuntimeException
{
}

/**
 * Fake error "bucket/object tidak ditemukan" ala Aws\S3\Exception\S3Exception (NotFound).
 */
final class FakeS3NotFound extends RuntimeException
{
}

/**
 * Fake error 404 realistis ala Aws\S3\Exception\S3Exception dengan getStatusCode().
 */
final class FakeS3Status404 extends RuntimeException
{
    public function getStatusCode(): int
    {
        return 404;
    }
}

/**
 * Fake stream body dengan __toString ala Psr7\Stream.
 */
final class FakeStream
{
    private string $content;

    public function __construct(string $content)
    {
        $this->content = $content;
    }

    public function __toString(): string
    {
        return $this->content;
    }
}
