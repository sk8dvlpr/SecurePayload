<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\Compression\PayloadCompressor;
use SecurePayload\Exceptions\SecurePayloadException;

/**
   * Unit PayloadCompressor.
  
   * Mencakup: roundtrip gzip/brotli, ambang MIN_SIZE, payload incompressible,
   * encoding asing ditolak (400), bomb guard (422), maxBytes custom, dan
   * pass-through identity/''.
  */
final class PayloadCompressorTest extends TestCase
{
    /** Body JSON besar yang mudah dikompresi (> MIN_SIZE). */
    private function compressible(int $targetLen = 8192): string
    {
        return json_encode([
            'data' => str_repeat('SecurePayload-compressible-', (int) ceil($targetLen / 27)),
            'flag' => true,
        ]) ?: '';
    }

    /** Encoding yang dipilih library pada lingkungan ini. */
    private function expectedEncoding(): string
    {
        return function_exists('brotli_compress') ? 'br' : 'gzip';
    }

    public function testRoundTripIdentik(): void
    {
        $raw = $this->compressible(8192);
        $res = PayloadCompressor::compress($raw);

        $this->assertSame($this->expectedEncoding(), $res['encoding'], 'Encoder harus memilih encoding terbaik yang tersedia.');
        $this->assertNotSame($raw, $res['data'], 'Body compressible harus benar-benar terkompresi.');
        $this->assertLessThan(strlen($raw), strlen($res['data']));
        $this->assertSame($raw, PayloadCompressor::decompress($res['data'], $res['encoding']));
    }

    public function testRoundTripBrotliJikaTersedia(): void
    {
        if (!function_exists('brotli_uncompress')) {
            $this->markTestSkipped('Ekstensi brotli tidak tersedia di lingkungan ini');
        }
        $raw = $this->compressible(4096);
        $packed = brotli_compress($raw);
        $this->assertNotFalse($packed);
        $this->assertSame($raw, PayloadCompressor::decompress((string) $packed, 'br'));
    }

    public function testPayloadKecilDariMinSizeIdentity(): void
    {
        $raw = '{"kecil":"ya"}';
        $res = PayloadCompressor::compress($raw);
        $this->assertSame(['data' => $raw, 'encoding' => 'identity'], $res, "Body di bawah MIN_SIZE harus lolos apa adanya sebagai identity.");
    }

    public function testDataAcakIncompressibleIdentity(): void
    {
        // Data acak nyaris tak bisa dikompresi → hasil >= 95% ukuran asli → identity.
        $raw = random_bytes(4096);
        $res = PayloadCompressor::compress($raw);
        $this->assertSame('identity', $res['encoding']);
        $this->assertSame($raw, $res['data']);
    }

    public function testEncodingAsingDitolakBadRequest(): void
    {
        try {
            PayloadCompressor::decompress('data', 'zstd');
            $this->fail('Encoding asing harus ditolak.');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::BAD_REQUEST, $e->getCode(), 'Encoding tidak dikenal harus 400 fail-closed.');
        }
    }

    public function testBombGuardMelebihiMaxBytesDefaultTidakTerjadi(): void
    {
        // 20 MB nol ber-gzip menjadi ~20 KB — jauh melebihi default 8 MiB saat didekompresi penuh,
        // jadi uji bomb dengan maxBytes eksplisit kecil (lihat testMaxBytesCustom).
        $bomb = gzencode(str_repeat('A', 20 * 1024 * 1024));
        $this->assertNotFalse($bomb);

        try {
            PayloadCompressor::decompress((string) $bomb, 'gzip', 1024 * 1024);
            $this->fail('Dekompresi bom melebihi maxBytes harus gagal.');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::UNPROCESSABLE, $e->getCode());
        }
    }

    public function testMaxBytesCustom(): void
    {
        $plain = str_repeat('A', 2048);
        $packed = gzencode($plain);
        $this->assertNotFalse($packed);

        // Di bawah batas custom → lolos utuh.
        $this->assertSame($plain, PayloadCompressor::decompress((string) $packed, 'gzip', 8192));

        // Di atas batas custom → UNPROCESSABLE.
        try {
            PayloadCompressor::decompress((string) $packed, 'gzip', 100);
            $this->fail('Hasil melebihi maxBytes custom harus gagal.');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::UNPROCESSABLE, $e->getCode());
        }
    }

    public function testIdentityDanEmptyLolosTanpaDiubah(): void
    {
        $this->assertSame('abc', PayloadCompressor::decompress('abc', ''));
        $this->assertSame('{"x":1}', PayloadCompressor::decompress('{"x":1}', 'identity'));
    }

    public function testGzipRusakDitolakUnprocessable(): void
    {
        try {
            PayloadCompressor::decompress('ini-bukan-gzip-sama-sekali', 'gzip');
            $this->fail('Data bukan gzip harus ditolak.');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::UNPROCESSABLE, $e->getCode());
        }
    }

    public function testBrotliTanpaEkstensiServerError(): void
    {
        if (function_exists('brotli_uncompress')) {
            $this->markTestSkipped('Ekstensi brotli tersedia — skenario tanpa brotli tidak dapat disimulasikan');
        }
        try {
            PayloadCompressor::decompress('data', 'br');
            $this->fail('br tanpa ekstensi brotli harus SERVER_ERROR fail-closed.');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::SERVER_ERROR, $e->getCode());
        }
    }
}
