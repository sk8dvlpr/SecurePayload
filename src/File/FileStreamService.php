<?php

declare(strict_types=1);

namespace SecurePayload\File;

use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\Internal\SecurePayloadConfig;
use SecurePayload\SecurePayload;

/**
 * Layanan transfer file streaming terenkripsi (secretstream).
 */
final class FileStreamService
{
    public function __construct(
        private SecurePayloadConfig $config,
    ) {
    }

    /**
     * Membangun Transfer File Streaming Terenkripsi (Client-Side, Phase 6).
     *
     * @param array{name?:string} $meta Metadata opsional (mis. nama file logis).
     *
     * @return array<string,mixed> Manifest (siap di-JSON-kan & ditandatangani).
     * @throws SecurePayloadException Jika sodium tidak ada, file tak terbaca, atau parameter salah.
     */
    public function buildFileStream(string $srcPath, string $destPath, array $meta = [], int $chunkSize = 65536): array
    {
        $this->config->ensureSodium();

        if ($chunkSize < 1024 || $chunkSize > SecurePayload::STREAM_MAX_CHUNK) {
            throw new SecurePayloadException('chunkSize di luar rentang wajar (1KiB–8MiB)', SecurePayloadException::BAD_REQUEST, ['chunkSize' => $chunkSize]);
        }
        if (!is_file($srcPath) || !is_readable($srcPath)) {
            throw new SecurePayloadException("File sumber tidak ditemukan/terbaca: $srcPath", SecurePayloadException::BAD_REQUEST);
        }

        $key = $this->config->deriveSubkey($this->config->getAeadKeyRaw(), SecurePayload::KDF_PURPOSE_AEAD_STREAM);
        $ad = FileValidation::streamAAD($this->config->getVersion());

        $in = fopen($srcPath, 'rb');
        if ($in === false) {
            throw new SecurePayloadException("Gagal membuka file sumber: $srcPath", SecurePayloadException::SERVER_ERROR);
        }
        $out = fopen($destPath, 'wb');
        if ($out === false) {
            fclose($in);
            throw new SecurePayloadException("Gagal membuka file tujuan: $destPath", SecurePayloadException::SERVER_ERROR);
        }

        try {
            [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);
            $cipherHash = hash_init('sha256');
            $plainSize = 0;
            $firstSniff = '';

            $cur = fread($in, $chunkSize);
            if ($cur === false) {
                $cur = '';
            }
            do {
                $next = '';
                if (!feof($in)) {
                    $read = fread($in, $chunkSize);
                    $next = $read === false ? '' : $read;
                }
                $isLast = ($next === '' && feof($in));
                $tag = $isLast
                    ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
                    : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;

                $cipher = sodium_crypto_secretstream_xchacha20poly1305_push($state, $cur, $ad, $tag);
                $frame = pack('N', strlen($cipher)) . $cipher;
                fwrite($out, $frame);
                hash_update($cipherHash, $frame);

                if ($firstSniff === '' && $cur !== '') {
                    $firstSniff = substr($cur, 0, 1024);
                }
                $plainSize += strlen($cur);
                $cur = $next;
            } while (!$isLast);

            $mime = (new \finfo(FILEINFO_MIME_TYPE))->buffer($firstSniff) ?: 'application/octet-stream';
            $name = basename((string) ($meta['name'] ?? basename($srcPath)));

            return [
                'v' => $this->config->getVersion(),
                'alg' => SecurePayload::STREAM_ALG,
                'name' => $name,
                'size' => $plainSize,
                'type' => $mime,
                'chunk_size' => $chunkSize,
                'header_b64' => base64_encode($header),
                'cipher_digest' => 'sha256=' . base64_encode(hash_final($cipherHash, true)),
            ];
        } finally {
            fclose($in);
            fclose($out);
        }
    }

    /**
     * Verifikasi & Dekripsi Transfer File Streaming (Server-Side, Phase 6).
     *
     * @param array<string,mixed> $manifest Manifest hasil buildFileStream (sudah diverifikasi via jalur request).
     * @param array<string,mixed> $constraints Sama seperti verifyFilePayload (max_size, allowed_exts, block_dangerous, strict_mime).
     *
     * @return array{ok:bool, status:int, error?:string, file?:array{name:string,size:int,type:string,path:string}}
     */
    public function verifyFileStream(string $encPath, array $manifest, string $destPath, array $constraints = []): array
    {
        $in = null;
        $out = null;
        try {
            $this->config->ensureSodium();

            $header = base64_decode((string) ($manifest['header_b64'] ?? ''), true);
            if (!is_string($header) || strlen($header) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) {
                return ['ok' => false, 'status' => 400, 'error' => 'Header stream pada manifest tidak valid'];
            }
            $expectSize = (int) ($manifest['size'] ?? -1);
            $expectDigest = (string) ($manifest['cipher_digest'] ?? '');
            $name = basename((string) ($manifest['name'] ?? 'unknown'));
            if ($expectSize < 0 || $expectDigest === '') {
                return ['ok' => false, 'status' => 400, 'error' => 'Manifest stream tidak lengkap'];
            }

            $maxSize = (int) ($constraints['max_size'] ?? 50 * 1024 * 1024); // default 50MB untuk file besar
            if ($expectSize > $maxSize) {
                return ['ok' => false, 'status' => 413, 'error' => "Ukuran file ($expectSize bytes) melebihi batas ($maxSize bytes)"];
            }

            $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
            $extErr = FileValidation::fileExtensionError($ext, $constraints);
            if ($extErr !== null) {
                return ['ok' => false, 'status' => $extErr[0], 'error' => $extErr[1]];
            }

            if (!is_file($encPath) || !is_readable($encPath)) {
                return ['ok' => false, 'status' => 400, 'error' => "File terenkripsi tidak ditemukan/terbaca: $encPath"];
            }

            $key = $this->config->deriveSubkey($this->config->getAeadKeyRaw(), SecurePayload::KDF_PURPOSE_AEAD_STREAM);
            $ad = FileValidation::streamAAD((string) ($manifest['v'] ?? $this->config->getVersion()));

            $in = fopen($encPath, 'rb');
            $out = fopen($destPath, 'wb');
            if ($in === false || $out === false) {
                $this->streamCleanup($in, $out, $destPath, true);
                return ['ok' => false, 'status' => 500, 'error' => 'Gagal membuka file untuk dekripsi stream'];
            }

            $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $key);
            $cipherHash = hash_init('sha256');
            $written = 0;
            $firstSniff = '';
            $sawFinal = false;
            $maxFrame = SecurePayload::STREAM_MAX_CHUNK + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

            while (true) {
                $lenRaw = FileValidation::freadExact($in, 4);
                if ($lenRaw === '') {
                    break; // EOF normal
                }
                if (strlen($lenRaw) !== 4) {
                    $this->streamCleanup($in, $out, $destPath, true);
                    return ['ok' => false, 'status' => 422, 'error' => 'Frame stream rusak (header panjang tidak lengkap)'];
                }
                /** @var array{1:int} $u */
                $u = unpack('N', $lenRaw);
                $len = $u[1];
                if ($len < SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES || $len > $maxFrame) {
                    $this->streamCleanup($in, $out, $destPath, true);
                    return ['ok' => false, 'status' => 422, 'error' => 'Panjang frame stream tidak wajar'];
                }
                $cipher = FileValidation::freadExact($in, $len);
                if (strlen($cipher) !== $len) {
                    $this->streamCleanup($in, $out, $destPath, true);
                    return ['ok' => false, 'status' => 422, 'error' => 'Stream terpotong (frame tidak lengkap)'];
                }
                hash_update($cipherHash, $lenRaw . $cipher);

                if ($sawFinal) {
                    // Ada data setelah penanda akhir → upaya append.
                    $this->streamCleanup($in, $out, $destPath, true);
                    return ['ok' => false, 'status' => 422, 'error' => 'Data tambahan setelah penanda akhir stream (append terdeteksi)'];
                }

                $res = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $cipher, $ad);
                if ($res === false) {
                    $this->streamCleanup($in, $out, $destPath, true);
                    return ['ok' => false, 'status' => 401, 'error' => 'Gagal mendekripsi chunk (data rusak atau dimodifikasi)'];
                }
                [$plain, $tag] = $res;

                if ($firstSniff === '' && $plain !== '') {
                    $firstSniff = substr($plain, 0, 1024);
                }
                fwrite($out, $plain);
                $written += strlen($plain);
                if ($written > $maxSize) {
                    $this->streamCleanup($in, $out, $destPath, true);
                    return ['ok' => false, 'status' => 413, 'error' => "Ukuran plaintext melebihi batas ($maxSize bytes)"];
                }
                if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                    $sawFinal = true;
                }
            }

            if (!$sawFinal) {
                $this->streamCleanup($in, $out, $destPath, true);
                return ['ok' => false, 'status' => 422, 'error' => 'Stream tidak lengkap (penanda akhir hilang — truncation)'];
            }

            $calcDigest = 'sha256=' . base64_encode(hash_final($cipherHash, true));
            if (!hash_equals($expectDigest, $calcDigest)) {
                $this->streamCleanup($in, $out, $destPath, true);
                return ['ok' => false, 'status' => 422, 'error' => 'Digest ciphertext tidak cocok dengan manifest'];
            }
            if ($written !== $expectSize) {
                $this->streamCleanup($in, $out, $destPath, true);
                return ['ok' => false, 'status' => 422, 'error' => "Ukuran plaintext ($written) tidak sesuai manifest ($expectSize)"];
            }

            $strict = (bool) ($constraints['strict_mime'] ?? true);
            $mimeErr = FileValidation::fileMimeError($firstSniff, $ext, $strict);
            if ($mimeErr !== null) {
                $this->streamCleanup($in, $out, $destPath, true);
                return ['ok' => false, 'status' => $mimeErr[0], 'error' => $mimeErr[1]];
            }

            $this->streamCleanup($in, $out, $destPath, false);
            return [
                'ok' => true,
                'status' => 200,
                'file' => [
                    'name' => $name,
                    'size' => $written,
                    'type' => (string) ($manifest['type'] ?? 'application/octet-stream'),
                    'path' => $destPath,
                ],
            ];
        } catch (\Throwable $e) {
            $this->streamCleanup($in, $out, $destPath, true);
            return ['ok' => false, 'status' => 500, 'error' => 'Kesalahan dekripsi stream: ' . $e->getMessage()];
        }
    }

    /**
     * Tutup handle stream dan (opsional) hapus file plaintext parsial saat gagal.
     *
     * @param resource|false|null $in
     * @param resource|false|null $out
     */
    public function streamCleanup($in, $out, string $destPath, bool $removeDest): void
    {
        if (is_resource($in)) {
            fclose($in);
        }
        if (is_resource($out)) {
            fclose($out);
        }
        if ($removeDest && is_file($destPath)) {
            @unlink($destPath);
        }
    }

    /**
     * Bangun body multipart/form-data (v4): part `payload` + `ciphertext`.
     *
     * @return array{boundary:string, body:string, content_type:string}
     */
    public static function buildMultipartBody(string $securedPayload, string $ciphertextBytes, ?string $boundary = null): array
    {
        $boundary = $boundary ?? ('sp-' . bin2hex(random_bytes(12)));
        $crlf = "\r\n";
        $body = '';
        $body .= '--' . $boundary . $crlf;
        $body .= 'Content-Disposition: form-data; name="payload"' . $crlf;
        $body .= 'Content-Type: application/json' . $crlf . $crlf;
        $body .= $securedPayload . $crlf;
        $body .= '--' . $boundary . $crlf;
        $body .= 'Content-Disposition: form-data; name="ciphertext"; filename="blob.bin"' . $crlf;
        $body .= 'Content-Type: application/octet-stream' . $crlf . $crlf;
        $body .= $ciphertextBytes . $crlf;
        $body .= '--' . $boundary . '--' . $crlf;

        return [
            'boundary' => $boundary,
            'body' => $body,
            'content_type' => 'multipart/form-data; boundary=' . $boundary,
        ];
    }

    /**
     * Parse body multipart sederhana (hanya part payload + ciphertext).
     *
     * @return array{payload:string, ciphertext:string}
     * @throws SecurePayloadException
     */
    public static function parseMultipartBody(string $body, string $contentType): array
    {
        if (!preg_match('/boundary=([^;\s]+)/i', $contentType, $m)) {
            throw new SecurePayloadException(
                'Content-Type multipart tanpa boundary',
                SecurePayloadException::BAD_REQUEST
            );
        }
        $boundary = trim($m[1], " \t\"'");
        $parts = preg_split('/\r\n--' . preg_quote($boundary, '/') . '(?:--)?\r\n/', "\r\n" . $body);
        if ($parts === false) {
            throw new SecurePayloadException('Gagal parse multipart', SecurePayloadException::BAD_REQUEST);
        }

        $payload = null;
        $ciphertext = null;
        foreach ($parts as $part) {
            $part = ltrim($part, "\r\n");
            if ($part === '' || $part === '--') {
                continue;
            }
            // Hilangkan penutup akhir --
            if (str_ends_with($part, '--')) {
                $part = substr($part, 0, -2);
            }
            $sep = strpos($part, "\r\n\r\n");
            if ($sep === false) {
                continue;
            }
            $rawHeaders = substr($part, 0, $sep);
            $content = substr($part, $sep + 4);
            // Trim trailing CRLF yang ditambahkan builder
            if (str_ends_with($content, "\r\n")) {
                $content = substr($content, 0, -2);
            }
            if (preg_match('/name="payload"/i', $rawHeaders)) {
                $payload = $content;
            } elseif (preg_match('/name="ciphertext"/i', $rawHeaders)) {
                $ciphertext = $content;
            }
        }

        if ($payload === null || $ciphertext === null) {
            throw new SecurePayloadException(
                'Multipart harus berisi part payload dan ciphertext',
                SecurePayloadException::BAD_REQUEST
            );
        }

        return ['payload' => $payload, 'ciphertext' => $ciphertext];
    }
}
