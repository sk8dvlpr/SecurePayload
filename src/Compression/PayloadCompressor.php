<?php

declare(strict_types=1);

namespace SecurePayload\Compression;

use SecurePayload\Exceptions\SecurePayloadException;

/**
 * Kompresi payload body — opt-in via opsi client `compress`.
 *
 * Desain penting:
 *  - Fitur OFF secara default; tanpa opsi `compress` wire protokol tidak berubah.
 *  - Digest/HMAC dihitung atas BYTE TERKOMPRESI oleh RequestBuilder, sehingga
 *    server mendekompresi hanya SETELAH integritas byte tersebut terverifikasi.
 *  - Kompresi dipilih otomatis: brotli bila ekstensi tersedia, selain itu gzip.
 *    Body pendek (< MIN_SIZE) atau incompressible (rasio hasil/asli >= MIN_RATIO)
 *    dikirim apa adanya dengan label 'identity'.
 *  - Dekompresi dijaga batas hasil (anti decompression-bomb) memakai pembacaan
 *    bertahap ber-streaming untuk gzip; brotli dicek pasca-dekompresi karena
 *    ekstensi brotli tidak menyediakan API streaming.
 */
final class PayloadCompressor
{
    /** Ukuran minimum body (byte) agar kompresi dicoba — di bawah ini selalu identity. */
    public const MIN_SIZE = 1024;

    /**
     * Rasio minimum manfaat (ukuran hasil / ukuran asli). Hasil >= 95% dari
     * ukuran asli dianggap tidak sebanding dengan biaya CPU → identity.
     */
    public const MIN_RATIO = 0.95;

    /** Batas default panjang hasil dekompresi: 8 MiB. */
    public const DEFAULT_MAX_BYTES = 8388608;

    /** Ukuran chunk pembacaan streaming saat inflasi terkendali. */
    private const CHUNK_SIZE = 65536;

    /**
     * Kompresi body JSON plaintext untuk pengiriman (client-side).
     *
     * Metode ini tidak pernah gagalkan request: bila ekstensi kompresi gagal,
     * body dikirim apa adanya sebagai 'identity'.
     *
     * @param string $raw Body JSON plaintext hasil json_encode.
     *
     * @return array{data:string, encoding:'gzip'|'br'|'identity'} Data yang
     *         dikirim beserta label encoding untuk header X-Payload-Encoding.
     */
    public static function compress(string $raw): array
    {
        // Terlalu kecil untuk bermanfaat — hindari overhead CPU + header.
        if (strlen($raw) < self::MIN_SIZE) {
            return ['data' => $raw, 'encoding' => 'identity'];
        }

        if (function_exists('brotli_compress')) {
            $compressed = brotli_compress($raw);
            $encoding = 'br';
        } else {
            $compressed = gzencode($raw);
            $encoding = 'gzip';
        }

        // Encoder gagal (jarang, mis. memori) → kirim apa adanya, jangan gagalkan request.
        if ($compressed === false) {
            return ['data' => $raw, 'encoding' => 'identity'];
        }

        // Data incompressible (acak/sudah terenkripsi): kompresi tak memberi manfaat.
        if (strlen($compressed) / strlen($raw) >= self::MIN_RATIO) {
            return ['data' => $raw, 'encoding' => 'identity'];
        }

        return ['data' => $compressed, 'encoding' => $encoding];
    }

    /**
     * Dekompresi body di sisi server sesuai nilai header X-Payload-Encoding.
     *
     * WAJIB dipanggil hanya SETELAH verifikasi integritas (digest/HMAC/AEAD)
     * atas $data berhasil. Pencocokan encoding bersifat ketat (lowercase) —
     * nilai lain di luar daftar dikenal ditolak fail-closed (400).
     *
     * @param string $data     Byte body yang sudah lolos verifikasi integritas.
     * @param string $encoding Nilai header X-Payload-Encoding (''/identity/gzip/br).
     * @param int    $maxBytes Batas maksimum panjang hasil dekompresi (anti bomb);
     *                         nilai <= 0 berarti tanpa batas (tidak disarankan).
     *
     * @return string Byte plaintext hasil dekompresi.
     *
     * @throws SecurePayloadException BAD_REQUEST bila encoding tidak dikenal;
     *         UNPROCESSABLE bila hasil melebihi $maxBytes atau data rusak;
     *         SERVER_ERROR bila 'br' diminta namun ekstensi brotli tidak tersedia.
     */
    public static function decompress(string $data, string $encoding, int $maxBytes = 8388608): string
    {
        switch ($encoding) {
            case '':
            case 'identity':
                return $data;
            case 'gzip':
                return self::inflateGzip($data, $maxBytes);
            case 'br':
                return self::inflateBrotli($data, $maxBytes);
            default:
                throw new SecurePayloadException(
                    'Encoding payload tidak didukung: ' . self::safeLabel($encoding),
                    SecurePayloadException::BAD_REQUEST
                );
        }
    }

    /**
     * Inflate gzip dengan guard ukuran ber-streaming (aman memori terhadap bom).
     *
     * Filter `zlib.inflate` dengan window 47 menangani kontainer gzip (deteksi
     * otomatis gzip/zlib). Pembacaan dilakukan per-chunk dan langsung dicek —
     * proses berhenti (throw) begitu akumulasi melebihi $maxBytes, tanpa
     * mengalokasikan seluruh hasil bom di memori.
     *
     * Catatan: data gzip terpotong di tengah stream bisa menghasilkan output
     * parsial tanpa sinyal error dari filter; risiko ini tertangani oleh
     * verifikasi integritas upstream (digest/HMAC/AEAD mengikat byte persis
     * seperti yang dikirim client terpercaya). Guard di sini bertugas membatasi
     * resource, bukan memvalidasi semantik gzip.
     */
    private static function inflateGzip(string $data, int $maxBytes): string
    {
        // Pre-check murah struktur kontainer gzip: magic 0x1F 0x8B + CM=8 (deflate).
        if (strlen($data) < 10 || $data[0] !== "\x1f" || $data[1] !== "\x8b" || ord($data[2]) !== 8) {
            throw new SecurePayloadException(
                'Data gzip rusak atau bukan kontainer gzip valid',
                SecurePayloadException::UNPROCESSABLE
            );
        }

        $mem = @fopen('php://temp', 'r+');
        if ($mem === false) {
            throw new SecurePayloadException(
                'Gagal menyiapkan stream dekompresi',
                SecurePayloadException::SERVER_ERROR
            );
        }
        fwrite($mem, $data);
        rewind($mem);

        $filter = @stream_filter_append($mem, 'zlib.inflate', STREAM_FILTER_READ, ['window' => 47]);
        if ($filter === false) {
            fclose($mem);
            return self::inflateGzipFallback($data, $maxBytes);
        }

        $out = '';
        while (!feof($mem)) {
            $chunk = fread($mem, self::CHUNK_SIZE);
            if ($chunk === false || $chunk === '') {
                break;
            }
            $out .= $chunk;
            if ($maxBytes > 0 && strlen($out) > $maxBytes) {
                fclose($mem); // filter otomatis dilepas saat stream ditutup
                throw self::bombException($maxBytes);
            }
        }
        fclose($mem);

        // Body protokol selalu JSON non-kosong; hasil kosong berarti data tidak valid.
        if ($out === '') {
            throw new SecurePayloadException(
                'Data gzip rusak atau tidak dapat didekompresi',
                SecurePayloadException::UNPROCESSABLE
            );
        }
        return $out;
    }

    /**
     * Jalur cadangan inflate gzip (filter stream tidak tersedia) memakai
     * gzdecode penuh + pengecekan ukuran pasca-dekompresi.
     */
    private static function inflateGzipFallback(string $data, int $maxBytes): string
    {
        if (!function_exists('gzdecode')) {
            throw new SecurePayloadException(
                'Dekompresi gzip tidak tersedia pada runtime PHP ini',
                SecurePayloadException::SERVER_ERROR
            );
        }
        $out = gzdecode($data);
        if ($out === false || $out === '') {
            throw new SecurePayloadException(
                'Data gzip rusak atau tidak dapat didekompresi',
                SecurePayloadException::UNPROCESSABLE
            );
        }
        if ($maxBytes > 0 && strlen($out) > $maxBytes) {
            throw self::bombException($maxBytes);
        }
        return $out;
    }

    /**
     * Inflate brotli. Ekstensi brotli tidak punya API streaming, sehingga guard
     * ukuran dilakukan pasca-dekompresi (dokumentasikan bila memakai 'br' pada
     * lingkungan dengan memori ketat).
     */
    private static function inflateBrotli(string $data, int $maxBytes): string
    {
        if (!function_exists('brotli_uncompress')) {
            throw new SecurePayloadException(
                'Encoding br memerlukan ekstensi brotli pada runtime PHP server',
                SecurePayloadException::SERVER_ERROR
            );
        }
        $out = brotli_uncompress($data);
        if ($out === false || $out === '') {
            throw new SecurePayloadException(
                'Data brotli rusak atau tidak dapat didekompresi',
                SecurePayloadException::UNPROCESSABLE
            );
        }
        if ($maxBytes > 0 && strlen($out) > $maxBytes) {
            throw self::bombException($maxBytes);
        }
        return $out;
    }

    private static function bombException(int $maxBytes): SecurePayloadException
    {
        return new SecurePayloadException(
            'Hasil dekompresi melebihi batas maksimum ' . $maxBytes . ' byte (potensi decompression-bomb)',
            SecurePayloadException::UNPROCESSABLE
        );
    }

    /**
     * Sanitasi nilai encoding (input tidak terpercaya) untuk dimasukkan ke
     * pesan exception: buang karakter kontrol/whitespace dan batasi panjang —
     * mencegah log-injection via header X-Payload-Encoding.
     */
    private static function safeLabel(string $encoding): string
    {
        $clean = preg_replace('/[^A-Za-z0-9._-]/', '', $encoding) ?? '';
        if ($clean === '') {
            return '(kosong/tidak valid)';
        }
        return substr($clean, 0, 32);
    }
}
