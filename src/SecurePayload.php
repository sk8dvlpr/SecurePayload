<?php

declare(strict_types=1);

namespace SecurePayload;

use SecurePayload\Client\RequestBuilder;
use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\File\FilePayloadService;
use SecurePayload\File\FileStreamService;
use SecurePayload\Http\CurlTransport;
use SecurePayload\Http\HttpTransportInterface;
use SecurePayload\Internal\SecurePayloadConfig;
use SecurePayload\Protocol\Aead;
use SecurePayload\Protocol\Canonical;
use SecurePayload\Protocol\Digest;
use SecurePayload\Protocol\Hkdf;
use SecurePayload\Protocol\Messages;
use SecurePayload\Response\ResponseBuilder;
use SecurePayload\Response\ResponseVerifier;
use SecurePayload\Server\ReplayGuard;
use SecurePayload\Server\RequestVerifier;

/**
 * SecurePayload
 * -------------
 * Kelas utilitas untuk mengamankan pertukaran data antara Client dan Server.
 * Menyediakan mekanisme otentikasi (HMAC), enkripsi (AEAD), anti-replay, dan validasi integritas.
 *
 * Facade publik — logika internal di modul Client/, Server/, Response/, File/, Protocol/.
 */
final class SecurePayload
{
    /** Header untuk Identitas Client */
    public const HX_CLIENT_ID = 'X-Client-Id';
    /** Header untuk ID Kunci */
    public const HX_KEY_ID = 'X-Key-Id';
    /** Header untuk Timestamp Request */
    public const HX_TIMESTAMP = 'X-Timestamp';
    /** Header untuk Nonce Unik */
    public const HX_NONCE = 'X-Nonce';
    /** Header Versi Tanda Tangan */
    public const HX_SIG_VER = 'X-Signature-Version';
    /** Header Algoritma Tanda Tangan */
    public const HX_SIG_ALG = 'X-Signature-Algorithm';
    /** Header Nilai Tanda Tangan (Signature) */
    public const HX_SIGNATURE = 'X-Signature';
    /** Header Digest dari Body (Integritas Data) */
    public const HX_BODY_DIGEST = 'X-Body-Digest';
    /** Header Canonical Request (Informasi path/method yang ditandatangani) */
    public const HX_CANON_REQ = 'X-Canonical-Request';
    /** Header Nonce untuk AEAD */
    public const HX_AEAD_NONCE = 'X-AEAD-Nonce';
    /** Header Algoritma AEAD */
    public const HX_AEAD_ALG = 'X-AEAD-Algorithm';

    // --- Header khusus RESPONSE (server menandatangani/mengenkripsi, client memverifikasi) ---
    /** Header Timestamp Response */
    public const HX_RESP_TIMESTAMP = 'X-Resp-Timestamp';
    /** Header Nonce acak Response */
    public const HX_RESP_NONCE = 'X-Resp-Nonce';
    /** Header Versi Tanda Tangan Response */
    public const HX_RESP_SIG_VER = 'X-Resp-Signature-Version';
    /** Header Algoritma Tanda Tangan Response */
    public const HX_RESP_SIG_ALG = 'X-Resp-Signature-Algorithm';
    /** Header Nilai Tanda Tangan Response */
    public const HX_RESP_SIGNATURE = 'X-Resp-Signature';
    /** Header Digest Body Response */
    public const HX_RESP_BODY_DIGEST = 'X-Resp-Body-Digest';
    /** Header Algoritma AEAD Response */
    public const HX_RESP_AEAD_ALG = 'X-Resp-AEAD-Algorithm';
    /** Header Nonce AEAD Response */
    public const HX_RESP_AEAD_NONCE = 'X-Resp-AEAD-Nonce';

    public const HMAC_ALG = 'HMAC-SHA256';
    /** Algoritma tanda tangan asimetris (Ed25519, libsodium) */
    public const ED25519_ALG = 'ED25519';
    /** Algoritma hybrid post-quantum: Ed25519 || ML-DSA-44 (Phase 18d) */
    public const HYBRID_ALG = 'HYBRID-MLDSA44-ED25519';
    /** Nilai opsi signAlg untuk hybrid */
    public const SIGN_ALG_HYBRID = 'hybrid-mldsa44-ed25519';
    public const AEAD_ALG = 'XCHACHA20-POLY1305-IETF';
    /** Marker header multipart file stream (protokol v4) */
    public const HX_MULTIPART = 'X-SP-Multipart';
    public const DEFAULT_VERSION = '4';

    /**
     * Label `info` HKDF per-fungsi untuk derivasi subkey (opsi `deriveKeys`).
     */
    public const KDF_PURPOSE_AEAD_REQ = 'sp-aead-req';
    public const KDF_PURPOSE_SIGN_REQ = 'sp-sign-req';
    public const KDF_PURPOSE_AEAD_RESP = 'sp-aead-resp';
    public const KDF_PURPOSE_SIGN_RESP = 'sp-sign-resp';
    public const KDF_PURPOSE_AEAD_STREAM = 'sp-aead-stream';

    /** Algoritma transfer file streaming (XChaCha20-Poly1305 secretstream). */
    public const STREAM_ALG = 'XCHACHA20POLY1305-SECRETSTREAM';

    /** Batas atas ukuran chunk streaming (8 MiB) — pagar terhadap frame berbahaya. */
    public const STREAM_MAX_CHUNK = 8 * 1024 * 1024;

    /**
     * Nama event keamanan yang diemit ke hook `onSecurityEvent` (Phase 8).
     */
    public const EVENT_TIMESTAMP_INVALID = 'timestamp_invalid';
    public const EVENT_REPLAY_DETECTED = 'replay_detected';
    public const EVENT_DECRYPT_FAILED = 'decrypt_failed';
    public const EVENT_SIGNATURE_INVALID = 'signature_invalid';
    public const EVENT_KEY_NOT_FOUND = 'key_not_found';
    public const EVENT_NONCE_MISMATCH = 'nonce_mismatch';

    private SecurePayloadConfig $config;
    private RequestBuilder $requestBuilder;
    private RequestVerifier $requestVerifier;
    private ResponseBuilder $responseBuilder;
    private ResponseVerifier $responseVerifier;
    private FilePayloadService $filePayloadService;
    private FileStreamService $fileStreamService;

    /**
     * Konstruktor SecurePayload
     *
     * @param array{
     *   mode?: 'hmac'|'aead'|'both',
     *   signAlg?: 'hmac'|'ed25519'|'hybrid-mldsa44-ed25519',
     *   version?: string,
     *   clientId?: string,
     *   keyId?: string,
     *   hmacSecretRaw?: string|null,
     *   ed25519SecretKeyB64?: string|null,
     *   ed25519PublicKeyServerB64?: string|null,
     *   ed25519SecretKeyServerB64?: string|null,
     *   mldsaSecretKeyB64?: string|null,
     *   mldsaPublicKeyB64?: string|null,
     *   mldsaSecretKeyServerB64?: string|null,
     *   mldsaPublicKeyServerB64?: string|null,
     *   pqSigner?: \SecurePayload\Crypto\PqSignerInterface|null,
     *   aeadKeyB64?: string|null,
     *   keyLoader?: callable|null,
     *   replayStore?: callable|null,
     *   replayTtl?: int,
     *   clockSkew?: int,
     *   bindHeaders?: list<string>,
     *   deriveKeys?: bool,
     *   onSecurityEvent?: callable|null,
     *   clock?: callable|null,
     *   nonceGenerator?: callable|null,
     *   respNonceGenerator?: callable|null,
     *   httpTransport?: HttpTransportInterface|callable():HttpTransportInterface|null
     * } $opts
     * @throws SecurePayloadException Jika konfigurasi tidak valid
     */
    public function __construct(array $opts = [])
    {
        $this->config = SecurePayloadConfig::fromOptions($opts);
        $replayGuard = new ReplayGuard($this->config);
        $this->requestBuilder = new RequestBuilder($this->config);
        $this->requestVerifier = new RequestVerifier($this->config, $replayGuard);
        $this->responseBuilder = new ResponseBuilder($this->config);
        $this->responseVerifier = new ResponseVerifier($this->config);
        $this->filePayloadService = new FilePayloadService($this->requestBuilder);
        $this->fileStreamService = new FileStreamService($this->config);
    }

    /**
     * Membangun Header Keamanan dan Body Request (Client-Side).
     *
     * @param array<string,string> $extraHeaders Header tambahan yang ikut dikirim.
     *
     * @return array{0: array<string,string>, 1: string} Tuple [Headers array, Body string]
     *
     * @throws SecurePayloadException Jika parameter salah atau enkripsi gagal
     */
    public function buildHeadersAndBody(string $url, string $method, array $payload, array $extraHeaders = []): array
    {
        return $this->requestBuilder->buildHeadersAndBody($url, $method, $payload, $extraHeaders);
    }

    /**
     * Mengirim HTTP request via transport yang dikonfigurasi.
     *
     * @param array<string,string> $headers
     *
     * @return array{status:int, headers:array<string,string>, body:mixed, error:?string}
     */
    private function executeHttp(string $url, string $method, string $body, array $headers): array
    {
        return $this->resolveHttpTransport()->send($url, $method, $body, $headers);
    }

    private function resolveHttpTransport(): HttpTransportInterface
    {
        $transport = $this->config->getHttpTransport();
        if ($transport instanceof HttpTransportInterface) {
            return $transport;
        }

        if (is_callable($transport)) {
            $resolved = $transport();
            if (!$resolved instanceof HttpTransportInterface) {
                throw new SecurePayloadException(
                    'Factory httpTransport harus mengembalikan HttpTransportInterface',
                    SecurePayloadException::SERVER_ERROR
                );
            }

            return $resolved;
        }

        if (extension_loaded('curl')) {
            return new CurlTransport();
        }

        throw new SecurePayloadException(
            'HTTP transport tidak tersedia. Set opsi httpTransport atau pasang ext-curl.',
            SecurePayloadException::SERVER_ERROR
        );
    }

    /**
     * Mengirim Request HTTP secara Sederhana (helper client).
     *
     * @param array<string,string> $extraHeaders Header tambahan jika diperlukan
     *
     * @return array{status:int, headers:array<string,string>, body:mixed, error:?string}
     */
    public function send(string $url, string $method, array $payload, array $extraHeaders = []): array
    {
        [$headers, $body] = $this->buildHeadersAndBody($url, $method, $payload, $extraHeaders);
        return $this->executeHttp($url, $method, $body, array_merge($headers, $extraHeaders));
    }

    /**
     * Membangun Payload Aman yang Berisi Lampiran File (Client-Side).
     *
     * @param array<string,string> $extraHeaders (Opsional) Header tambahan yang ikut dikirim.
     *
     * @return array{0: array<string,string>, 1: string}
     *
     * @throws SecurePayloadException Jika file tidak ditemukan atau tidak dapat dibaca.
     */
    public function buildFilePayload(string $url, string $method, string $filePath, array $data = [], ?string $customFileName = null, array $extraHeaders = []): array
    {
        return $this->filePayloadService->buildFilePayload($url, $method, $filePath, $data, $customFileName, $extraHeaders);
    }

    /**
     * Mengirim File secara Aman (Client-Side).
     *
     * @param array<string,string> $extraHeaders (Opsional) Header tambahan curl
     *
     * @return array{status:int, headers:array<string,string>, body:mixed, error:?string}
     */
    public function sendFile(string $url, string $method, string $filePath, array $data = [], ?string $customFileName = null, array $extraHeaders = []): array
    {
        [$headers, $body] = $this->buildFilePayload($url, $method, $filePath, $data, $customFileName, $extraHeaders);
        return $this->executeHttp($url, $method, $body, array_merge($headers, $extraHeaders));
    }

    /**
     * Verifikasi Request (Server-Side) - Aman, tanpa Exception.
     *
     * @param array|string $query Query string atau array query
     *
     * @return array{ok:bool, status?:int, error?:string, debug?:array<string,mixed>, mode?:string, bodyPlain?:string, json?:mixed}
     */
    public function verify(array $headers, string $rawBody, string $method, string $path, $query): array
    {
        try {
            $data = $this->verifyOrThrow($headers, $rawBody, $method, $path, $query);
            return ['ok' => true] + $data;
        } catch (SecurePayloadException $e) {
            return [
                'ok' => false,
                'status' => $e->getCode() ?: SecurePayloadException::BAD_REQUEST,
                'error' => $e->getMessage(),
                'debug' => $e->getContext(),
                'mode' => '',
                'bodyPlain' => '',
                'json' => null,
            ];
        }
    }

    /**
     * Verifikasi Request dengan Exception jika tidak valid.
     *
     * @param array|string $query
     *
     * @return array{mode:string, bodyPlain:string|null, json:mixed}
     * @throws SecurePayloadException Jika verifikasi gagal.
     */
    public function verifyOrThrow(array $headers, string $rawBody, string $method, string $path, $query): array
    {
        return $this->requestVerifier->verifyOrThrow($headers, $rawBody, $method, $path, $query);
    }

    /**
     * Helper Verifikasi Sederhana (Deprecated Behavior Fixed).
     *
     * @return array{ok:bool, status?:int, error?:string, debug?:array<string,mixed>, mode?:string, bodyPlain?:string, json:mixed}
     */
    public function verifySimple(array $headers, string $rawBody, string $method, string $path): array
    {
        return $this->verify($headers, $rawBody, $method, $path, []);
    }

    /**
     * Verifikasi Payload File di Sisi Server.
     *
     * @param array<string,mixed> $constraints Opsi konfigurasi pembatasan file.
     *
     * @return array{
     *   ok: bool,
     *   file: ?array{name:string, size:int, type:string, content_b64:string, content_decoded:string},
     *   data: mixed,
     *   error?: string,
     *   status?: int
     * }
     */
    public function verifyFilePayload(array $headers, string $rawBody, string $method, string $path, array $constraints = []): array
    {
        return $this->filePayloadService->verifyFilePayload(
            $headers,
            $rawBody,
            $method,
            $path,
            $constraints,
            fn (array $h, string $b, string $m, string $p): array => $this->verifySimple($h, $b, $m, $p)
        );
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
        return $this->fileStreamService->buildFileStream($srcPath, $destPath, $meta, $chunkSize);
    }

    /**
     * Verifikasi & Dekripsi Transfer File Streaming (Server-Side, Phase 6).
     *
     * @param array<string,mixed> $manifest Manifest hasil buildFileStream (sudah diverifikasi via jalur request).
     * @param array<string,mixed> $constraints Sama seperti verifyFilePayload.
     *
     * @return array{ok:bool, status:int, error?:string, file?:array{name:string,size:int,type:string,path:string}}
     */
    public function verifyFileStream(string $encPath, array $manifest, string $destPath, array $constraints = []): array
    {
        return $this->fileStreamService->verifyFileStream($encPath, $manifest, $destPath, $constraints);
    }

    /**
     * Bangun request multipart file stream (protokol v4).
     *
     * Signature/HMAC/AEAD mencakup body SP dari **manifest** (via buildHeadersAndBody).
     * Body HTTP adalah multipart: part `payload` = body SP tersign/terenkripsi; part `ciphertext` = bytes stream.
     *
     * @param array{name?:string} $meta
     * @param array<string,string> $extraHeaders
     * @return array{0: array<string,string>, 1: string, 2: string} [headers, multipartBody, contentType]
     */
    public function buildFileStreamMultipartRequest(
        string $url,
        string $method,
        string $srcPath,
        array $meta = [],
        int $chunkSize = 65536,
        array $extraHeaders = []
    ): array {
        $encTmp = tempnam(sys_get_temp_dir(), 'sp_enc_');
        if ($encTmp === false) {
            throw new SecurePayloadException('Gagal membuat temp file ciphertext', SecurePayloadException::SERVER_ERROR);
        }
        try {
            $manifest = $this->fileStreamService->buildFileStream($srcPath, $encTmp, $meta, $chunkSize);
            $ciphertext = file_get_contents($encTmp);
            if ($ciphertext === false) {
                throw new SecurePayloadException('Gagal membaca ciphertext stream', SecurePayloadException::SERVER_ERROR);
            }
            [$headers, $securedBody] = $this->buildHeadersAndBody($url, $method, $manifest, $extraHeaders);
            $mp = FileStreamService::buildMultipartBody($securedBody, $ciphertext);
            $headers['Content-Type'] = $mp['content_type'];
            $headers[self::HX_MULTIPART] = '1';
            return [$headers, $mp['body'], $mp['content_type']];
        } finally {
            if (is_file($encTmp)) {
                @unlink($encTmp);
            }
        }
    }

    /**
     * Verifikasi request multipart file stream (v4): parse → verify payload → verifyFileStream.
     *
     * @param array<string,string> $headers
     * @param array<string,mixed>|string $query
     * @param array<string,mixed> $constraints
     * @return array{ok:bool,status?:int,error?:string,verify?:array<string,mixed>,file?:array<string,mixed>}
     */
    public function verifyFileStreamMultipart(
        array $headers,
        string $multipartBody,
        string $method,
        string $path,
        $query,
        string $destPath,
        array $constraints = []
    ): array {
        $norm = [];
        foreach ($headers as $k => $v) {
            $norm[strtoupper((string) $k)] = (string) $v;
        }
        $contentType = $norm['CONTENT-TYPE'] ?? '';
        try {
            $parts = FileStreamService::parseMultipartBody($multipartBody, $contentType);
        } catch (SecurePayloadException $e) {
            return ['ok' => false, 'status' => $e->getCode() ?: 400, 'error' => $e->getMessage()];
        }

        $verify = $this->verify($headers, $parts['payload'], $method, $path, $query);
        if (!$verify['ok']) {
            return ['ok' => false, 'status' => $verify['status'] ?? 401, 'error' => $verify['error'] ?? 'verify gagal', 'verify' => $verify];
        }

        $manifest = $verify['json'] ?? null;
        if (!is_array($manifest)) {
            return ['ok' => false, 'status' => 422, 'error' => 'Manifest JSON tidak valid setelah verify'];
        }

        $encTmp = tempnam(sys_get_temp_dir(), 'sp_enc_');
        if ($encTmp === false) {
            return ['ok' => false, 'status' => 500, 'error' => 'Gagal membuat temp ciphertext'];
        }
        try {
            file_put_contents($encTmp, $parts['ciphertext']);
            $fileRes = $this->verifyFileStream($encTmp, $manifest, $destPath, $constraints);
            if (!$fileRes['ok']) {
                return ['ok' => false, 'status' => $fileRes['status'] ?? 422, 'error' => $fileRes['error'] ?? 'stream gagal', 'verify' => $verify];
            }
            return ['ok' => true, 'status' => 200, 'verify' => $verify, 'file' => $fileRes['file'] ?? null];
        } finally {
            if (is_file($encTmp)) {
                @unlink($encTmp);
            }
        }
    }

    /**
     * Membangun Response Aman (Server-Side).
     *
     * @param array<mixed> $payload Data response.
     *
     * @return array{0: array<string,string>, 1: string} Tuple [Headers response, Body string]
     * @throws SecurePayloadException Jika kredensial/kunci tidak tersedia atau enkripsi gagal.
     */
    public function buildResponse(array $requestHeaders, array $payload): array
    {
        return $this->responseBuilder->buildResponse($requestHeaders, $payload);
    }

    /**
     * Verifikasi Response Aman (Client-Side) — aman, tanpa Exception.
     *
     * @return array{ok:bool, status?:int, error?:string, debug?:array<string,mixed>, mode?:string, bodyPlain?:string, json?:mixed}
     */
    public function verifyResponse(array $headers, string $rawBody, string $reqNonceB64): array
    {
        try {
            $data = $this->verifyResponseOrThrow($headers, $rawBody, $reqNonceB64);
            return ['ok' => true] + $data;
        } catch (SecurePayloadException $e) {
            return [
                'ok' => false,
                'status' => $e->getCode() ?: SecurePayloadException::BAD_REQUEST,
                'error' => $e->getMessage(),
                'debug' => $e->getContext(),
                'mode' => '',
                'bodyPlain' => '',
                'json' => null,
            ];
        }
    }

    /**
     * Verifikasi Response dengan Exception jika tidak valid (Client-Side).
     *
     * @return array{mode:string, bodyPlain:string|null, json:mixed}
     * @throws SecurePayloadException Jika verifikasi gagal.
     */
    public function verifyResponseOrThrow(array $headers, string $rawBody, string $reqNonceB64): array
    {
        return $this->responseVerifier->verifyResponseOrThrow($headers, $rawBody, $reqNonceB64);
    }

    /**
     * Turunkan subkey 32-byte dari sebuah master key memakai HKDF-SHA256.
     *
     * @throws SecurePayloadException Jika master kosong atau derivasi gagal.
     */
    public static function deriveKey(string $master, string $purpose, int $len = 32): string
    {
        return Hkdf::deriveKey($master, $purpose, $len);
    }

    /** Normalisasi path URL. */
    public static function normalizePath(string $path): string
    {
        return Canonical::normalizePath($path);
    }

    /**
     * Canonicalisasi Query String.
     *
     * @param array<string,mixed> $q
     */
    public static function canonicalQuery(array $q): string
    {
        return Canonical::canonicalQuery($q);
    }

    /** Generate nonce acak 16 byte (Base64). */
    public static function genNonceB64(): string
    {
        return Digest::genNonceB64();
    }

    /** Hitung SHA-256 digest dari string body. */
    public static function bodyDigestB64(string $body): string
    {
        return Digest::bodyDigestB64($body);
    }

    public static function buildRequestAeadAad(string $version, string $ts, array $boundHeaders = []): string
    {
        return Aead::buildRequestAeadAad($version, $ts, $boundHeaders);
    }

    /**
     * AAD untuk enkripsi RESPONSE (publik untuk spesifikasi / conformance).
     */
    public static function buildResponseAeadAad(string $version, string $reqNonceB64, string $respTs): string
    {
        return Aead::buildResponseAeadAad($version, $reqNonceB64, $respTs);
    }

    /**
     * Turunkan AEAD Nonce 24-byte (XChaCha20) yang terikat dengan request context.
     */
    public static function aeadNonceFrom(string $nonceB64, string $method, string $path, string $qStr): string
    {
        return Aead::aeadNonceFrom($nonceB64, $method, $path, $qStr);
    }

    /**
     * Buat Pesan Kanonik untuk HMAC.
     */
    public static function hmacMessage(string $ver, string $clientId, string $keyId, string $ts, string $nonceB64, string $method, string $path, string $qStr, string $bodyDigestB64): string
    {
        return Messages::hmacMessage($ver, $clientId, $keyId, $ts, $nonceB64, $method, $path, $qStr, $bodyDigestB64);
    }

    /**
     * Turunkan AEAD Nonce 24-byte untuk RESPONSE, terikat ke nonce response
     * acak dan nonce request asal (binding dua arah).
     */
    public static function respAeadNonceFrom(string $respNonceB64, string $reqNonceB64): string
    {
        return Aead::respAeadNonceFrom($respNonceB64, $reqNonceB64);
    }

    /**
     * Pesan Kanonik untuk tanda tangan RESPONSE.
     */
    public static function respMessage(string $ver, string $reqNonceB64, string $respTs, string $respNonceB64, string $bodyDigestB64): string
    {
        return Messages::respMessage($ver, $reqNonceB64, $respTs, $respNonceB64, $bodyDigestB64);
    }
}
