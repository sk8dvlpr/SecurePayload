<?php
declare(strict_types=1);

namespace SecurePayload\Storage\Internal;

use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\SecurePayload;
use Throwable;

/**
 * Codec internal untuk blob ciphertext storage self-contained.
 *
 * Format blob: secretstream_header (24 byte raw) ‖ frames, dengan
 * frame = pack('N', len) . cipher dan TAG_FINAL wajib di chunk akhir.
 * Framing ini MENIRU (duplikasi sadar, ±50 baris) pola di
 * \SecurePayload\File\FileStreamService::buildFileStream/verifyFileStream —
 * JANGAN mengubah salah satu format tanpa sinkronisasi keduanya.
 * Perbedaan disengaja: codec ini buffer penuh in-memory (blob string),
 * bukan stream file-ke-file.
 *
 * @internal Hanya untuk pemakaian internal SecureFileStorage.
 */
final class EnvelopeCodec
{
    private function __construct()
    {
        // Kelas utilitas statis murni — tidak bisa diinstansiasi.
    }

    /**
     * Pastikan ekstensi sodium tersedia (fail-closed).
     *
     * @throws SecurePayloadException SERVER_ERROR bila ext-sodium tidak ada.
     */
    public static function ensureSodium(): void
    {
        if (!extension_loaded('sodium')) {
            throw new SecurePayloadException('Ekstensi sodium diperlukan untuk storage terenkripsi', SecurePayloadException::SERVER_ERROR);
        }
    }

    /**
     * Enkripsi seluruh isi $in menjadi satu blob ciphertext self-contained.
     *
     * @param resource $in Handle file sumber terbuka (mode 'rb'); dibaca per $chunkSize.
     * @param string   $dek  Data Encryption Key mentah (32 byte) — TIDAK pernah masuk blob.
     * @param string   $aadFrame AAD biner yang mengikat setiap frame (v + file_id).
     * @param int      $chunkSize Ukuran chunk plaintext per frame (sudah divalidasi pemanggil).
     *
     * @return array{blob:string, size:int, digest:string} blob=header+frames, size=plaintext byte, digest='sha256=<b64>'.
     *
     * @throws SecurePayloadException Bila enkripsi gagal.
     */
    public static function encryptStream($in, string $dek, string $aadFrame, int $chunkSize): array
    {
        self::ensureSodium();
        try {
            [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($dek);
            // Akumulasi frame via array + implode: concat '.=' per frame memicu
            // realokasi string super-linear (terukur 40MB: 356ms vs 133ms).
            $parts = [$header];
            $size = 0;
            // fread() === false berarti I/O error tanpa EOF — fail-closed, JANGAN
            // dikonversi ke '' (loop tak akan pernah mencapai TAG_FINAL → infinite
            // loop membesarkan blob dengan frame kosong). File 0-byte tetap aman:
            // fread di sana mengembalikan '' bukan false.
            $cur = fread($in, $chunkSize);
            if ($cur === false) {
                throw new SecurePayloadException('Gagal membaca file sumber saat enkripsi', SecurePayloadException::SERVER_ERROR);
            }
            do {
                $next = '';
                if (!feof($in)) {
                    $read = fread($in, $chunkSize);
                    if ($read === false) {
                        throw new SecurePayloadException('Gagal membaca file sumber saat enkripsi', SecurePayloadException::SERVER_ERROR);
                    }
                    $next = $read;
                }
                $isLast = ($next === '' && feof($in));
                $tag = $isLast
                    ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
                    : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;

                $cipher = sodium_crypto_secretstream_xchacha20poly1305_push($state, $cur, $aadFrame, $tag);
                // Frame identik format FileStreamService: pack('N',len)+cipher.
                $parts[] = pack('N', strlen($cipher)) . $cipher;
                $size += strlen($cur);
                $cur = $next;
            } while (!$isLast);
            $blob = implode('', $parts);
        } catch (SecurePayloadException $e) {
            throw $e; // Pesan spesifik (mis. gagal baca file) tidak boleh tertelan wrapper generik.
        } catch (Throwable $e) {
            throw new SecurePayloadException('Gagal mengenkripsi blob: kesalahan kriptografi internal', SecurePayloadException::SERVER_ERROR);
        }

        return [
            'blob' => $blob,
            'size' => $size,
            'digest' => 'sha256=' . base64_encode(hash('sha256', $blob, true)),
        ];
    }

    /**
     * Dekripsi blob self-contained menjadi plaintext string penuh.
     *
     * Verifikasi fail-closed:
     * - header cukup panjang & state pull valid;
     * - TAG_FINAL harus tercapai (menolak truncation);
     * - tidak boleh ada data setelah TAG_FINAL (menolak append attack);
     * - AAD/frame mismatch atau tamper → sodium gagal → exception.
     *
     * Trade-off memori: plaintext penuh berada di memori (≤ ukuran file).
     *
     * @throws SecurePayloadException UNAUTHORIZED bila autentikasi frame gagal,
     *                                UNPROCESSABLE bila struktur blob rusak/truncated/appended.
     */
    public static function decryptStream(string $blob, string $dek, string $aadFrame): string
    {
        self::ensureSodium();
        $headerLen = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES; // 24
        $abytes = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;         // 17
        // Frame minimal: hanya auth tag (plaintext kosong); maksimum: chunk 8MiB + tag.
        $minFrame = $abytes;
        $maxFrame = SecurePayload::STREAM_MAX_CHUNK + $abytes;

        if (strlen($blob) < $headerLen + $minFrame) {
            throw new SecurePayloadException('Blob ciphertext terlalu pendek / rusak', SecurePayloadException::UNPROCESSABLE);
        }

        try {
            $header = substr($blob, 0, $headerLen);
            $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $dek);
        } catch (Throwable $e) {
            throw new SecurePayloadException('Header stream blob tidak valid', SecurePayloadException::UNPROCESSABLE);
        }

        // Akumulasi plaintext via array + implode: concat '.=' per frame memicu
        // realokasi string super-linear pada file besar.
        $parts = [];
        $sawFinal = false;
        $pos = $headerLen;
        $len = strlen($blob);
        while ($pos < $len) {
            if ($sawFinal) {
                // Data setelah penanda akhir → upaya append.
                throw new SecurePayloadException('Data tambahan setelah penanda akhir stream (append terdeteksi)', SecurePayloadException::UNPROCESSABLE);
            }
            if ($len - $pos < 4) {
                throw new SecurePayloadException('Blob rusak (panjang frame tidak lengkap)', SecurePayloadException::UNPROCESSABLE);
            }
            /** @var array{1:int} $u */
            $u = unpack('N', substr($blob, $pos, 4));
            $frameLen = $u[1];
            $pos += 4;
            if ($frameLen < $minFrame || $frameLen > $maxFrame) {
                throw new SecurePayloadException('Panjang frame blob tidak wajar', SecurePayloadException::UNPROCESSABLE);
            }
            if ($len - $pos < $frameLen) {
                throw new SecurePayloadException('Blob terpotong (frame tidak lengkap)', SecurePayloadException::UNPROCESSABLE);
            }
            $cipher = substr($blob, $pos, $frameLen);
            $pos += $frameLen;

            $res = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $cipher, $aadFrame);
            if ($res === false) {
                throw new SecurePayloadException('Gagal mendekripsi chunk (data rusak, dimodifikasi, atau AAD tidak cocok)', SecurePayloadException::UNAUTHORIZED);
            }
            /** @var array{0:string,1:int} $res */
            [$plain, $tag] = $res;
            $parts[] = $plain;
            if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                $sawFinal = true;
            }
        }

        if (!$sawFinal) {
            throw new SecurePayloadException('Blob tidak lengkap (penanda akhir hilang — truncation)', SecurePayloadException::UNPROCESSABLE);
        }

        return implode('', $parts);
    }
}
