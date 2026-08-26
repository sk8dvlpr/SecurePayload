<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\Storage\FileManifest;

/**
 * Unit test FileManifest: round-trip serialisasi & validasi fail-closed.
 */
final class FileManifestTest extends TestCase
{
    /** @return array<string,mixed> Struktur manifest valid lengkap. */
    private function validData(): array
    {
        return [
            'v' => '1',
            'alg' => 'XCHACHA20POLY1305-SECRETSTREAM',
            'file_id' => str_repeat('ab', 16),
            'kek_id' => 'test-kek',
            'wrapped_dek_b64' => base64_encode(random_bytes(64)),
            'aad_context' => ['file_id' => str_repeat('ab', 16), 'kek_id' => 'test-kek', 'purpose' => 'securepayload-file-dek'],
            'size' => 1234,
            'cipher_digest' => 'sha256=' . base64_encode(hash('sha256', 'x', true)),
            'chunk_size' => 65536,
            'created_at' => 1700000000,
            'metadata' => ['name' => 'dokumen.pdf'],
        ];
    }

    public function testRoundTrip_ToArrayFromArray_Identik(): void
    {
        $data = $this->validData();
        $m = FileManifest::fromArray($data);

        $this->assertSame($data, $m->toArray(), 'toArray harus mengembalikan struktur identik dengan input.');

        // Round-trip kedua harus stabil (idempoten).
        $m2 = FileManifest::fromArray($m->toArray());
        $this->assertSame($m->toArray(), $m2->toArray());
    }

    public function testGetters_MengembalikanNilaiSesuaiInput(): void
    {
        $data = $this->validData();
        $m = FileManifest::fromArray($data);

        $this->assertSame('1', $m->v());
        $this->assertSame('XCHACHA20POLY1305-SECRETSTREAM', $m->alg());
        $this->assertSame(str_repeat('ab', 16), $m->fileId());
        $this->assertSame('test-kek', $m->kekId());
        $this->assertSame($data['wrapped_dek_b64'], $m->wrappedDekB64());
        $this->assertSame($data['aad_context'], $m->aadContext());
        $this->assertSame(1234, $m->size());
        $this->assertSame($data['cipher_digest'], $m->cipherDigest());
        $this->assertSame(65536, $m->chunkSize());
        $this->assertSame(1700000000, $m->createdAt());
        $this->assertSame(['name' => 'dokumen.pdf'], $m->metadata());
    }

    /**
     * @return list<string> Daftar semua field wajib.
     */
    public function providerRequiredFields(): array
    {
        return [
            ['v'],
            ['alg'],
            ['file_id'],
            ['kek_id'],
            ['wrapped_dek_b64'],
            ['aad_context'],
            ['size'],
            ['cipher_digest'],
            ['chunk_size'],
            ['created_at'],
            ['metadata'],
        ];
    }

    /** @dataProvider providerRequiredFields */
    public function testFieldWajibHilang_SatuSatu_Throw(string $field): void
    {
        $data = $this->validData();
        unset($data[$field]);

        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionCode(SecurePayloadException::BAD_REQUEST);
        FileManifest::fromArray($data);
    }

    /**
     * @return list<array{string,mixed}> Pasangan [field, nilai salah].
     */
    public function providerWrongTypes(): array
    {
        return [
            ['size', '1234'],          // numeric-string, bukan int
            ['size', 12.5],            // float
            ['chunk_size', '65536'],
            ['created_at', '1700000000'],
            ['created_at', null],
            ['aad_context', 'bukan-array'],
            ['metadata', ['x' => 123]], // value bukan string
            ['metadata', [123 => 'x']], // key bukan string
        ];
    }

    /** @dataProvider providerWrongTypes */
    public function testTipeSalah_Throw(string $field, $value): void
    {
        $data = $this->validData();
        $data[$field] = $value;

        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionCode(SecurePayloadException::BAD_REQUEST);
        FileManifest::fromArray($data);
    }

    /**
     * @return list<array{string}> file_id tidak valid.
     */
    public function providerInvalidFileIds(): array
    {
        return [
            ['../etc/passwd'],
            [strtoupper(str_repeat('ab', 16))],   // uppercase hex
            [str_repeat('a', 31)],                // 31 char
            [str_repeat('a', 33)],                // 33 char
            ['zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'], // bukan hex
        ];
    }

    /** @dataProvider providerInvalidFileIds */
    public function testFileIdTidakValid_Throw(string $fileId): void
    {
        $data = $this->validData();
        $data['file_id'] = $fileId;

        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionCode(SecurePayloadException::BAD_REQUEST);
        FileManifest::fromArray($data);
    }

    public function testWrappedDekBukanBase64_Throw(): void
    {
        $data = $this->validData();
        $data['wrapped_dek_b64'] = 'bukan-base64!!!';

        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionCode(SecurePayloadException::BAD_REQUEST);
        FileManifest::fromArray($data);
    }

    public function testCipherDigestTanpaPrefixSha256_Throw(): void
    {
        $data = $this->validData();
        $data['cipher_digest'] = 'md5=abc';

        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionCode(SecurePayloadException::BAD_REQUEST);
        FileManifest::fromArray($data);
    }

    public function testStringFieldKosong_Throw(): void
    {
        $data = $this->validData();
        $data['kek_id'] = '';

        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionCode(SecurePayloadException::BAD_REQUEST);
        FileManifest::fromArray($data);
    }
}
