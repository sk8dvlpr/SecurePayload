<?php

declare(strict_types=1);

namespace SecurePayload\File;

use SecurePayload\Client\RequestBuilder;
use SecurePayload\Exceptions\SecurePayloadException;

/**
 * Layanan transfer file in-memory (base64 dalam payload JSON).
 */
final class FilePayloadService
{
    public function __construct(
        private RequestBuilder $requestBuilder,
    ) {
    }

    /**
     * Membangun Payload Aman yang Berisi Lampiran File (Client-Side).
     *
     * @param array<string,string> $extraHeaders (Opsional) Header tambahan yang ikut dikirim;
     *                                    yang terdaftar pada `bindHeaders` diikat ke AAD AEAD.
     *
     * @return array{0: array<string,string>, 1: string}
     *
     * @throws SecurePayloadException Jika file tidak ditemukan atau tidak dapat dibaca.
     */
    public function buildFilePayload(string $url, string $method, string $filePath, array $data = [], ?string $customFileName = null, array $extraHeaders = []): array
    {
        if (!is_file($filePath) || !is_readable($filePath)) {
            throw new SecurePayloadException("File tidak ditemukan atau tidak terbaca: $filePath", SecurePayloadException::BAD_REQUEST);
        }

        $content = file_get_contents($filePath);
        if ($content === false) {
            throw new SecurePayloadException("Gagal membaca file: $filePath", SecurePayloadException::BAD_REQUEST);
        }

        $finfo = new \finfo(FILEINFO_MIME_TYPE);
        $mime = $finfo->buffer($content) ?: 'application/octet-stream';
        $name = FileValidation::sanitizeFileName($customFileName ?: basename($filePath));
        $size = strlen($content);

        // Gabungkan data body dengan metadata file
        // Struktur: { ...data, _attachment: { name, size, type, content_b64 } }
        $payload = $data;
        $payload['_attachment'] = [
            'name' => $name,
            'size' => $size,
            'type' => $mime,
            'content' => base64_encode($content),
        ];

        return $this->requestBuilder->buildHeadersAndBody($url, $method, $payload, $extraHeaders);
    }

    /**
     * Verifikasi Payload File di Sisi Server.
     *
     * @param array  $headers   Array header dari request (gunakan `getallheaders()`).
     * @param string $rawBody   String body mentah dari request (gunakan `file_get_contents('php://input')`).
     * @param string $method    HTTP Method yang diterima server.
     * @param string $path      URL Path yang diterima server.
     * @param array  $constraints Opsi konfigurasi pembatasan file.
     * @param array|string $query Query string / array dari request server (bukan dari header klien).
     * @param callable(array<string,string>, string, string, string, array|string): array<string,mixed> $verify
     *        Callback verifikasi dasar (mis. verify).
     *
     * @return array{
     *   ok: bool,
     *   file: ?array{name:string, size:int, type:string, content_b64:string, content_decoded:string},
     *   data: mixed,
     *   error?: string,
     *   status?: int
     * }
     */
    public function verifyFilePayload(array $headers, string $rawBody, string $method, string $path, array $constraints, $query, callable $verify): array
    {
        // 1. Verifikasi Keamanan Dasar (Signature/Encryption) — query dari server
        $res = $verify($headers, $rawBody, $method, $path, $query);
        if (($res['ok'] ?? false) === false) {
            return $res + ['file' => null, 'data' => null];
        }

        $json = $res['json'];
        $attachment = $json['_attachment'] ?? null;
        $data = $json;
        unset($data['_attachment']); // Pisahkan data bersih dari attachment

        if (!$attachment || !is_array($attachment)) {
            return [
                'ok' => false,
                'status' => 400,
                'error' => 'Tidak ada lampiran file dalam payload',
                'file' => null,
                'data' => $data,
            ];
        }

        // 2. Validasi Metadata File
        $name = FileValidation::sanitizeFileName((string) ($attachment['name'] ?? 'unknown'));
        $claimedSize = (int) ($attachment['size'] ?? 0);
        $contentB64 = is_string($attachment['content'] ?? null) ? $attachment['content'] : '';

        $maxSize = (int) ($constraints['max_size'] ?? 5 * 1024 * 1024); // 5MB

        // Tolak sebelum decode: field size ATAU estimasi base64 melebihi max (anti DoS alokasi).
        $b64Len = strlen($contentB64);
        $estimatedDecoded = (int) floor($b64Len * 3 / 4);
        if ($claimedSize > $maxSize || $estimatedDecoded > $maxSize) {
            return [
                'ok' => false,
                'status' => 413,
                'error' => "Ukuran file melebihi batas ($maxSize bytes)",
                'file' => null,
                'data' => $data,
            ];
        }

        $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
        $extErr = FileValidation::fileExtensionError($ext, $constraints);
        if ($extErr !== null) {
            return ['ok' => false, 'status' => $extErr[0], 'error' => $extErr[1], 'file' => null, 'data' => $data];
        }

        // 3. Decode Content
        $decoded = base64_decode($contentB64, true);
        if ($decoded === false) {
            return [
                'ok' => false,
                'status' => 400,
                'error' => 'Gagal decode konten file',
                'file' => null,
                'data' => $data,
            ];
        }

        $actualSize = strlen($decoded);
        if ($actualSize > $maxSize) {
            return [
                'ok' => false,
                'status' => 413,
                'error' => "Ukuran file ($actualSize bytes) melebihi batas ($maxSize bytes)",
                'file' => null,
                'data' => $data,
            ];
        }

        if ($actualSize !== $claimedSize) {
            return [
                'ok' => false,
                'status' => 400,
                'error' => 'Integritas ukuran file tidak valid',
                'file' => null,
                'data' => $data,
            ];
        }

        // 4. Strict MIME Type & Security Verification (Deep Scan) — anti-spoofing.
        $strict = $constraints['strict_mime'] ?? true;
        $mimeErr = FileValidation::fileMimeError($decoded, $ext, (bool) $strict);
        if ($mimeErr !== null) {
            return ['ok' => false, 'status' => $mimeErr[0], 'error' => $mimeErr[1], 'file' => null, 'data' => $data];
        }

        return [
            'ok' => true,
            'status' => 200,
            'file' => [
                'name' => $name,
                'size' => $actualSize,
                'type' => $attachment['type'] ?? 'application/octet-stream',
                'content_b64' => $contentB64,
                'content_decoded' => $decoded,
            ],
            'data' => $data,
        ];
    }
}
