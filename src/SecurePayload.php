<?php

declare(strict_types=1);

namespace SecurePayload;

use RuntimeException;
use SecurePayload\Exceptions\SecurePayloadException;

/**
 * SecurePayload
 * -------------
 * Kelas utilitas untuk mengamankan pertukaran data antara Client dan Server.
 * Menyediakan mekanisme otentikasi (HMAC), enkripsi (AEAD), anti-replay, dan validasi integritas.
 *
 * Fitur Utama:
 * - Mode Keamanan: 'hmac' (Tanda tangan saja), 'aead' (Enkripsi saja), 'both' (Enkripsi + Tanda tangan).
 * - Proteksi Replay: Menggunakan Nonce dan Timestamp dengan toleransi waktu.
 * - Key Management: Mendukung loading key dari sumber eksternal (Database, KMS, Env).
 * - Standar Kriptografi: Menggunakan SHA-256 untuk hashing dan XChaCha20-Poly1305 untuk enkripsi (jika tersedia).
 *
 * Contoh Penggunaan Singkat:
 * - Client: Menggunakan `buildHeadersAndBody()` untuk membuat payload aman.
 * - Server: Menggunakan `verify()` untuk memvalidasi request yang masuk.
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
    public const AEAD_ALG = 'XCHACHA20-POLY1305-IETF';
    public const DEFAULT_VERSION = '3';

    /**
     * Label `info` HKDF per-fungsi untuk derivasi subkey (opsi `deriveKeys`).
     * Setiap fungsi memakai label berbeda sehingga kompromi satu subkey tidak
     * meruntuhkan fungsi lain (pemisahan domain). Label diikat ke versi protokol
     * saat derivasi (lihat deriveSubkey()), bukan dipakai mentah.
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
     * Berguna untuk integrasi SIEM / rate-limiter. Context yang dikirim TIDAK
     * pernah memuat material rahasia (secret/plaintext/ciphertext).
     */
    public const EVENT_TIMESTAMP_INVALID = 'timestamp_invalid';
    public const EVENT_REPLAY_DETECTED = 'replay_detected';
    public const EVENT_DECRYPT_FAILED = 'decrypt_failed';
    public const EVENT_SIGNATURE_INVALID = 'signature_invalid';
    public const EVENT_KEY_NOT_FOUND = 'key_not_found';
    public const EVENT_NONCE_MISMATCH = 'nonce_mismatch';

    /** @var 'hmac'|'aead'|'both' Mode keamanan yang digunakan */
    private string $mode;

    /** @var 'hmac'|'ed25519' Algoritma tanda tangan untuk mode hmac/both */
    private string $signAlg;

    /** @var string Versi protokol */
    private string $version;

    private ?string $clientId;
    private ?string $keyId;
    private ?string $hmacSecretRaw;
    private ?string $aeadKeyB64;

    /** @var string|null Secret key Ed25519 (base64, 64 byte) untuk signing di sisi client */
    private ?string $ed25519SecretKeyB64;

    /** @var callable(string,string): array{hmacSecret:?string,aeadKeyB64:?string}|null Fungsi untuk memuat kunci */
    private $keyLoader;

    /** @var callable(string,int): bool|null Fungsi kustom untuk penyimpanan replay cache */
    private $replayStore;

    /** @var int Time-to-live untuk replay protection (detik) */
    private int $replayTtl;

    /** @var int Toleransi perbedaan waktu jam server (detik) */
    private int $clockSkew;

    /**
     * @var list<string> Nama header kritikal yang nilainya diikat ke AAD AEAD
     *                   (mis. 'Content-Type'). Perubahan nilainya otomatis
     *                   menggagalkan dekripsi. Harus sama di client & server.
     */
    private array $bindHeaders;

    /**
     * @var bool Jika true, kunci HMAC & AEAD yang disuplai diperlakukan sebagai
     *           MASTER key; subkey per-fungsi diturunkan via HKDF (hash_hkdf).
     *           Memberi pemisahan domain antar fungsi (enkripsi req/resp, signing
     *           req/resp). WAJIB sama di client & server. Default: false (kunci
     *           dipakai langsung, kompatibel dengan perilaku lama).
     */
    private bool $deriveKeys;

    /**
     * @var callable(string, array<string,mixed>): void|null Hook event keamanan.
     *      Dipanggil saat terjadi event seperti replay/signature gagal/dekripsi
     *      gagal. Murni observasional — tidak mengubah alur verifikasi. Exception
     *      dari callback ditelan agar tidak mengganggu keamanan.
     */
    private $onSecurityEvent;

    /**
     * Konstruktor SecurePayload
     *
     * Konfigurasi yang didukung dalam $opts:
     * - mode: 'hmac' | 'aead' | 'both' (Default: 'both')
     * - signAlg: 'hmac' | 'ed25519' Algoritma tanda tangan untuk mode hmac/both (Default: 'hmac')
     *            'ed25519' memakai kriptografi asimetris: client menandatangani dengan
     *            private key, server memverifikasi dengan public key (non-repudiation).
     * - version: Versi protokol (Default: '3')
     * - clientId: ID Client (Wajib untuk mode Client)
     * - keyId: ID Key (Wajib untuk mode Client)
     * - hmacSecretRaw: Secret key untuk HMAC (Raw string, dipakai jika signAlg='hmac')
     * - ed25519SecretKeyB64: Secret key Ed25519 base64 64-byte (Client, dipakai jika signAlg='ed25519')
     * - aeadKeyB64: Secret key untuk AEAD (Base64 string)
     * - keyLoader: Callable untuk memuat kunci di sisi server
     * - replayStore: Callable untuk custom storage replay protection.
     *                ⚠️  WAJIB di lingkungan multi-server/load-balancer.
     *                    File-based cache bawaan TIDAK terbagi antar worker server.
     *                    Implementasikan dengan Redis/Memcached untuk produksi.
     *                    Signature: callable(string $cacheKey, int $ttl): bool
     *                    Return true jika nonce baru (belum pernah dipakai), false jika replay.
     * - replayTtl: Durasi validitas nonce dalam detik (Default: 120)
     * - clockSkew: Toleransi perbedaan jam dalam detik (Default: 60)
     * - bindHeaders: Daftar nama header kritikal (mis. ['Content-Type']) yang
     *                nilainya diikat ke AAD AEAD. Manipulasi nilainya otomatis
     *                menggagalkan dekripsi. WAJIB identik di client & server.
     *                Nilai header di sisi client disuplai lewat $extraHeaders pada
     *                buildHeadersAndBody()/send(); di sisi server dibaca dari header
     *                request masuk. Timestamp (X-Timestamp) selalu diikat otomatis.
     * - deriveKeys: Jika true, kunci HMAC & AEAD yang disuplai diperlakukan sebagai
     *               MASTER key dan subkey per-fungsi diturunkan via HKDF-SHA256
     *               (pemisahan domain: enkripsi/sign untuk request/response memakai
     *               subkey berbeda). WAJIB identik di client & server. Tidak berlaku
     *               untuk signing Ed25519 (sudah asimetris). Default: false.
     * - onSecurityEvent: Callback observasional `fn(string $event, array $context): void`
     *               yang dipanggil saat event keamanan terjadi (replay terdeteksi,
     *               signature gagal, dekripsi gagal, timestamp di luar batas, key
     *               tidak ditemukan, nonce mismatch). Untuk integrasi SIEM/rate-limit.
     *               Context TIDAK pernah memuat secret/plaintext. Exception dari
     *               callback ditelan (tidak memengaruhi verifikasi).
     *
     * @param array{
     *   mode?: 'hmac'|'aead'|'both',
     *   signAlg?: 'hmac'|'ed25519',
     *   version?: string,
     *   clientId?: string,
     *   keyId?: string,
     *   hmacSecretRaw?: string|null,
     *   ed25519SecretKeyB64?: string|null,
     *   aeadKeyB64?: string|null,
     *   keyLoader?: callable|null,
     *   replayStore?: callable|null,
     *   replayTtl?: int,
     *   clockSkew?: int,
     *   bindHeaders?: list<string>,
     *   deriveKeys?: bool,
     *   onSecurityEvent?: callable|null
     * } $opts
     * @throws SecurePayloadException Jika konfigurasi tidak valid
     */
    public function __construct(array $opts = [])
    {
        $this->mode = $opts['mode'] ?? 'both';
        $this->version = $opts['version'] ?? self::DEFAULT_VERSION;
        $this->clientId = $opts['clientId'] ?? null;
        $this->keyId = $opts['keyId'] ?? null;
        $this->hmacSecretRaw = $opts['hmacSecretRaw'] ?? null;
        if (
            isset($this->hmacSecretRaw) &&
            $this->hmacSecretRaw !== null &&
            strlen($this->hmacSecretRaw) < 32
        ) {
            throw new SecurePayloadException(
                'HMAC Secret terlalu pendek. Minimum 32 karakter (rekomendasikan 64 byte hex).',
                SecurePayloadException::BAD_REQUEST
            );
        }
        $this->aeadKeyB64 = $opts['aeadKeyB64'] ?? null;
        $this->ed25519SecretKeyB64 = $opts['ed25519SecretKeyB64'] ?? null;
        $this->signAlg = $opts['signAlg'] ?? 'hmac';
        $this->keyLoader = $opts['keyLoader'] ?? null;
        $this->replayStore = $opts['replayStore'] ?? null;
        $this->replayTtl = isset($opts['replayTtl']) ? (int) $opts['replayTtl'] : 120;
        $this->clockSkew = isset($opts['clockSkew']) ? (int) $opts['clockSkew'] : 60;

        // Daftar header kritikal yang diikat ke AAD. Disaring agar hanya berisi
        // nama header non-kosong (string) demi konsistensi binding client-server.
        $this->bindHeaders = [];
        if (isset($opts['bindHeaders']) && is_array($opts['bindHeaders'])) {
            foreach ($opts['bindHeaders'] as $h) {
                if (is_string($h) && $h !== '') {
                    $this->bindHeaders[] = $h;
                }
            }
        }

        $this->deriveKeys = !empty($opts['deriveKeys']);

        $hook = $opts['onSecurityEvent'] ?? null;
        $this->onSecurityEvent = is_callable($hook) ? $hook : null;

        if (!in_array($this->mode, ['hmac', 'aead', 'both'], true)) {
            throw new SecurePayloadException('Mode tidak valid: ' . $this->mode, SecurePayloadException::BAD_REQUEST);
        }
        if (!in_array($this->signAlg, ['hmac', 'ed25519'], true)) {
            throw new SecurePayloadException('signAlg tidak valid: ' . $this->signAlg, SecurePayloadException::BAD_REQUEST);
        }
        // Validasi panjang secret key Ed25519 jika disuplai (sisi client).
        if (
            $this->ed25519SecretKeyB64 !== null &&
            $this->ed25519SecretKeyB64 !== ''
        ) {
            $skRaw = base64_decode($this->ed25519SecretKeyB64, true);
            if (!is_string($skRaw) || strlen($skRaw) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
                throw new SecurePayloadException(
                    'Secret key Ed25519 tidak valid (harus base64 dari 64 byte)',
                    SecurePayloadException::BAD_REQUEST
                );
            }
        }
        if ($this->version === '') {
            throw new SecurePayloadException('Versi tidak boleh kosong', SecurePayloadException::BAD_REQUEST);
        }
    }

    /**
     * Membangun Header Keamanan dan Body Request (Client-Side).
     *
     * Fungsi ini mempersiapkan data yang akan dikirim ke server sesuai dengan mode keamanan.
     * Mengembalikan array berisi headers yang harus disertakan dan body yang sudah diproses (misal dienkripsi).
     *
     * @param string $url     URL lengkap tujuan request (misal: https://api.com/v1/data?q=1)
     * @param string $method  HTTP Method (GET, POST, dll)
     * @param array  $payload Data payload dalam bentuk array asosiatif
     * @param array<string,string> $extraHeaders Header tambahan yang ikut dikirim.
     *               Header yang namanya terdaftar pada opsi `bindHeaders` akan
     *               diikat ke AAD AEAD; nilainya HARUS sama dengan yang benar-benar
     *               dikirim ke server agar dekripsi tidak gagal.
     *
     * @return array{0: array<string,string>, 1: string} Tuple [Headers array, Body string]
     *
     * @throws SecurePayloadException Jika parameter salah atau enkripsi gagal
     */
    public function buildHeadersAndBody(string $url, string $method, array $payload, array $extraHeaders = []): array
    {
        // Validasi kebutuhan kredensial dasar
        if (($this->clientId ?? '') === '' || ($this->keyId ?? '') === '') {
            throw new SecurePayloadException('clientId & keyId wajib diisi untuk mode client', SecurePayloadException::BAD_REQUEST);
        }

        $method = strtoupper($method);
        $parts = parse_url($url);
        if ($parts === false) {
            throw new SecurePayloadException('Format URL tidak valid', SecurePayloadException::BAD_REQUEST);
        }

        $path = self::normalizePath($parts['path'] ?? '/');
        $qStr = '';
        if (!empty($parts['query'])) {
            parse_str($parts['query'], $qArr);
            if (!is_array($qArr)) {
                $qArr = [];
            }
            $qStr = self::canonicalQuery($qArr);
        }

        $ver = $this->version;
        $ts = (string) time();
        $nonceB64 = self::genNonceB64();

        // Nilai header kritikal yang diikat ke AAD diambil dari header tambahan
        // yang akan benar-benar dikirim. Server membaca nilai yang sama dari
        // request masuk, sehingga AAD identik di kedua sisi.
        $boundHeaders = $this->collectBoundHeaders($extraHeaders);

        // Header dasar yang selalu ada. Header tambahan digabung lebih dahulu
        // agar header keamanan tidak bisa ditimpa oleh caller.
        $headers = array_merge($extraHeaders, [
            self::HX_CLIENT_ID => (string) $this->clientId,
            self::HX_KEY_ID => (string) $this->keyId,
            self::HX_TIMESTAMP => $ts,
            self::HX_NONCE => $nonceB64,
            self::HX_SIG_VER => $ver,
                // X-Canonical-Request dikirim sebagai debugging hint, BUKAN source of truth untuk keamanan server
            self::HX_CANON_REQ => base64_encode($method . "\n" . $path . "\n" . $qStr),
        ]);

        // --- MODE: AEAD (Enkripsi Saja) ---
        if ($this->mode === 'aead') {
            $body = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if ($body === false) {
                throw new SecurePayloadException('Gagal encode JSON payload', SecurePayloadException::BAD_REQUEST);
            }
            $this->ensureSodium();

            $aeadKeyRaw = $this->deriveSubkey($this->getAeadKeyRaw(), self::KDF_PURPOSE_AEAD_REQ);
            $aeadNonce = self::aeadNonceFrom($nonceB64, $method, $path, $qStr);

            // Enkripsi body
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $body,
                $this->aeadAAD($ver, $ts, $boundHeaders),
                $aeadNonce,
                $aeadKeyRaw
            );
            $bodyB64 = base64_encode($ciphertext);

            $headers[self::HX_AEAD_ALG] = self::AEAD_ALG;
            $headers[self::HX_AEAD_NONCE] = base64_encode($aeadNonce);

            // Output body dibungkus JSON khusus
            return [$headers, json_encode(['__aead_b64' => $bodyB64], JSON_UNESCAPED_SLASHES)];
        }

        // --- MODE: BOTH (Enkripsi + HMAC) ---
        if ($this->mode === 'both') {
            $plain = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if ($plain === false) {
                throw new SecurePayloadException('Gagal encode JSON payload', SecurePayloadException::BAD_REQUEST);
            }
            $this->ensureSodium();

            $aeadKeyRaw = $this->deriveSubkey($this->getAeadKeyRaw(), self::KDF_PURPOSE_AEAD_REQ);
            $aeadNonce = self::aeadNonceFrom($nonceB64, $method, $path, $qStr);

            // Enkripsi
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $plain,
                $this->aeadAAD($ver, $ts, $boundHeaders),
                $aeadNonce,
                $aeadKeyRaw
            );
            $ctB64 = base64_encode($ciphertext);
            $body = json_encode(['__aead_b64' => $ctB64], JSON_UNESCAPED_SLASHES);

            // Tanda tangan dilakukan terhadap Plaintext asli, bukan ciphertext
            // agar server memverifikasi makna data, bukan bungkusnya.
            $digestB64 = self::bodyDigestB64($plain);
            $msg = self::hmacMessage($ver, (string) $this->clientId, (string) $this->keyId, $ts, $nonceB64, $method, $path, $qStr, $digestB64);
            [$sigB64, $sigAlg] = $this->signCanonical($msg);

            $headers[self::HX_AEAD_ALG] = self::AEAD_ALG;
            $headers[self::HX_AEAD_NONCE] = base64_encode($aeadNonce);
            $headers[self::HX_SIG_ALG] = $sigAlg;
            $headers[self::HX_BODY_DIGEST] = 'sha256=' . $digestB64;
            $headers[self::HX_SIGNATURE] = $sigB64;

            return [$headers, $body];
        }

        // --- MODE: HMAC (Tanda Tangan Saja) ---
        $plain = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($plain === false) {
            throw new SecurePayloadException('Gagal encode JSON payload', SecurePayloadException::BAD_REQUEST);
        }

        $digestB64 = self::bodyDigestB64($plain);
        $msg = self::hmacMessage($ver, (string) $this->clientId, (string) $this->keyId, $ts, $nonceB64, $method, $path, $qStr, $digestB64);
        [$sigB64, $sigAlg] = $this->signCanonical($msg);

        $headers[self::HX_SIG_ALG] = $sigAlg;
        $headers[self::HX_BODY_DIGEST] = 'sha256=' . $digestB64;
        $headers[self::HX_SIGNATURE] = $sigB64;

        return [$headers, $plain];
    }

    /**
     * Mengeksekusi HTTP request via cURL.
     *
     * @param string $url URL tujuan.
     * @param string $method HTTP method (GET, POST, dll).
     * @param string $body Body request yang sudah diproses.
     * @param array<string,string> $headers Security headers + extra headers.
     *
     * @return array{status:int, headers:array<string,string>, body:mixed, error:?string}
     */
    private function executeCurl(string $url, string $method, string $body, array $headers): array
    {
        if (!extension_loaded('curl')) {
            throw new SecurePayloadException('Ekstensi cURL diperlukan', SecurePayloadException::SERVER_ERROR);
        }

        $outHeaders = [];
        foreach ($headers as $k => $v) {
            $outHeaders[] = $k . ': ' . $v;
        }
        $outHeaders[] = 'Content-Type: application/json';

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $outHeaders);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

        $resp = curl_exec($ch);
        $err = $resp === false ? curl_error($ch) : null;
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);

        $rawHeaders = substr((string) $resp, 0, $headerSize);
        $bodyStr = substr((string) $resp, $headerSize);

        $respHeaders = [];
        foreach (preg_split("/\r?\n/", $rawHeaders) as $line) {
            if (strpos($line, ':') !== false) {
                [$hk, $hv] = array_map('trim', explode(':', $line, 2));
                if ($hk !== '') {
                    $respHeaders[$hk] = $hv;
                }
            }
        }

        $json = json_decode($bodyStr, true);
        return [
            'status' => $code,
            'headers' => $respHeaders,
            'body' => $json !== null ? $json : $bodyStr,
            'error' => $err,
        ];
    }

    /**
     * Mengirim Request HTTP secara Sederhana (Helper Wrapper cURL).
     *
     * @param string $url URL Tujuan
     * @param string $method HTTP Method
     * @param array $payload Data Payload
     * @param array<string,string> $extraHeaders Header tambahan jika diperlukan
     * 
     * @return array{status:int, headers:array<string,string>, body:mixed, error:?string}
     */
    public function send(string $url, string $method, array $payload, array $extraHeaders = []): array
    {
        [$headers, $body] = $this->buildHeadersAndBody($url, $method, $payload, $extraHeaders);
        return $this->executeCurl($url, $method, $body, array_merge($headers, $extraHeaders));
    }

    /**
     * Membangun Payload Aman yang Berisi Lampiran File (Client-Side).
     *
     * Fungsi ini mempermudah proses pembuatan body request yang menyertakan file.
     * File akan dibaca, dikonversi ke format Base64 standard, lalu digabungkan dengan data JSON lainnya
     * ke dalam struktur payload internal `_attachment`.
     *
     * Hasil dari fungsi ini adalah array headers dan string body yang siap dikirim,
     * yang mana body tersebut sudah dienkripsi (AEAD) atau ditandatangani (HMAC) sesuai mode.
     *
     * @param string $url            URL lengkap tujuan request, digunakan untuk perhitungan signature.
     * @param string $method         HTTP Method (GET, POST, PUT, dll).
     * @param string $filePath       Lokasi absolut atau relatif file fisik yang akan dikirim.
     * @param array  $data           (Opsional) Data tambahan dalam bentuk key-value array yang ingin disertakan bersama file.
     *                               Contoh: ['user_id' => 123, 'keterangan' => 'Foto Profil'].
     * @param string|null $customFileName (Opsional) Nama kustom untuk file tersebut saat diterima server.
     *                                    Jika null, akan menggunakan nama asli dari file fisik.
     * @param array<string,string> $extraHeaders (Opsional) Header tambahan yang ikut dikirim;
     *                                    yang terdaftar pada `bindHeaders` diikat ke AAD AEAD.
     *
     * @warning Seluruh konten file dimuat ke memori PHP sebelum diproses dan dikonversi
     *          ke Base64 (+33% overhead). JANGAN gunakan method ini untuk file >10MB
     *          tanpa meningkatkan `memory_limit` PHP secara eksplisit.
     *          Untuk transfer file besar, pertimbangkan menggunakan multipart/form-data
     *          standar dan hanya sign/verify hash file-nya saja via payload JSON biasa.
     *
     * @return array{0: array<string,string>, 1: string} 
     *         Mengembalikan array tuple:
     *         - Index 0: Array Headers keamanan (X-Signature, X-Nonce, dll).
     *         - Index 1: String Body request siap kirim (JSON/Encrypted String).
     *
     * @throws SecurePayloadException Jika file tidak ditemukan atau tidak dapat dibaca.
     */
    public function buildFilePayload(string $url, string $method, string $filePath, array $data = [], ?string $customFileName = null, array $extraHeaders = []): array
    {
        if (!file_exists($filePath) || !is_readable($filePath)) {
            throw new SecurePayloadException("File tidak ditemukan atau tidak terbaca: $filePath", SecurePayloadException::BAD_REQUEST);
        }

        $content = file_get_contents($filePath);
        if ($content === false) {
            throw new SecurePayloadException("Gagal membaca file: $filePath", SecurePayloadException::BAD_REQUEST);
        }

        $finfo = new \finfo(FILEINFO_MIME_TYPE);
        $mime = $finfo->buffer($content) ?: 'application/octet-stream';
        $name = $customFileName ?: basename($filePath);
        $size = strlen($content);

        // Gabungkan data body dengan metadata file
        // Struktur: { ...data, _attachment: { name, size, type, content_b64 } }
        $payload = $data;
        $payload['_attachment'] = [
            'name' => $name,
            'size' => $size,
            'type' => $mime,
            'content' => base64_encode($content)
        ];

        return $this->buildHeadersAndBody($url, $method, $payload, $extraHeaders);
    }

    /**
     * Mengirim File secara Aman (Client-Side).
     * 
     * Wrapper praktis untuk mengirim file. Data body opsional.
     * 
     * @param string $url URL Tujuan
     * @param string $method HTTP Method
     * @param string $filePath Path file
     * @param array  $data (Opsional) Data body tambahan
     * @param string|null $customFileName (Opsional) Nama file
     * @param array  $extraHeaders (Opsional) Header tambahan curl
     * 
     * @return array{status:int, headers:array<string,string>, body:mixed, error:?string}
     */
    public function sendFile(string $url, string $method, string $filePath, array $data = [], ?string $customFileName = null, array $extraHeaders = []): array
    {
        [$headers, $body] = $this->buildFilePayload($url, $method, $filePath, $data, $customFileName, $extraHeaders);
        return $this->executeCurl($url, $method, $body, array_merge($headers, $extraHeaders));
    }

    /**
     * Verifikasi Request (Server-Side) - Aman, tanpa Exception.
     * 
     * Membungkus `verifyOrThrow` dalam try-catch untuk kemudahan penggunaan.
     *
     * @param array<string,string> $headers Header dari request masuk
     * @param string $rawBody Body mentah dari request
     * @param string $method HTTP Method yang diterima server (WAJIB)
     * @param string $path URL Path yang diterima server (WAJIB)
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
                'mode' => "",
                'bodyPlain' => "",
                'json' => null,
            ];
        }
    }

    /**
     * Verifikasi Request dengan Exception jika tidak valid.
     *
     * Tahapan verifikasi:
     * 1. Cek kelengkapan header wajib.
     * 2. Validasi Timestamp (mencegah expired request).
     * 3. Validasi Replay Attack (mencegah penggunaan ulang nonce).
     * 4. Memuat kunci rahasia berdasarkan Client ID & Key ID.
     * 5. Dekripsi (jika mode AEAD/BOTH) dan Verifikasi Signature (jika mode HMAC/BOTH).
     *
     * @param array<string,string> $headers
     * @param string $rawBody
     * @param string $method
     * @param string $path
     * @param array|string $query
     * 
     * @return array{mode:string, bodyPlain:string|null, json:mixed}
     * @throws SecurePayloadException Jika verifikasi gagal.
     */
    public function verifyOrThrow(array $headers, string $rawBody, string $method, string $path, $query): array
    {
        // Normalisasi header key menjadi uppercase untuk pencarian case-insensitive (pseudo)
        $H = [];
        foreach ($headers as $k => $v) {
            if (!is_string($k))
                continue;
            $H[strtoupper($k)] = (string) $v;
        }

        $ver = $H[self::upper(self::HX_SIG_VER)] ?? '';
        $cid = $H[self::upper(self::HX_CLIENT_ID)] ?? '';
        $kid = $H[self::upper(self::HX_KEY_ID)] ?? '';
        $tsStr = $H[self::upper(self::HX_TIMESTAMP)] ?? '';
        $nonceB64 = $H[self::upper(self::HX_NONCE)] ?? '';

        // 1. Validasi Keberadaan Header
        if ($ver === '' || $cid === '' || $kid === '' || $tsStr === '' || $nonceB64 === '') {
            throw new SecurePayloadException('Header keamanan tidak lengkap', SecurePayloadException::BAD_REQUEST);
        }
        if ($ver !== $this->version) {
            throw new SecurePayloadException('Versi protokol tidak didukung', SecurePayloadException::BAD_REQUEST, ['terima' => $ver, 'ekspektasi' => $this->version]);
        }

        // 2. Validasi Timestamp
        if (!preg_match('/^\d+$/', $tsStr)) {
            throw new SecurePayloadException('Format timestamp salah', SecurePayloadException::BAD_REQUEST, ['nilai' => $tsStr]);
        }
        $ts = (int) $tsStr;
        $now = time();

        // Cek range waktu: tidak boleh masa depan (skew) dan tidak boleh terlalu lampau (ttl + skew)
        if ($ts > $now + $this->clockSkew || $ts < $now - ($this->replayTtl + $this->clockSkew)) {
            $this->emitEvent(self::EVENT_TIMESTAMP_INVALID, ['clientId' => $cid, 'keyId' => $kid, 'ts' => $ts, 'now' => $now]);
            throw new SecurePayloadException('Timestamp di luar batas wajar (kadaluarsa atau jam salah)', SecurePayloadException::UNAUTHORIZED, ['ts' => $ts, 'now' => $now]);
        }

        // 3. Proteksi Replay Attack
        $this->checkReplay($cid, $kid, $tsStr, $nonceB64);

        // Menyiapkan parameter request kanonik dari input Server (BUKAN dari header X-Canonical-Request)
        $method = strtoupper($method);
        $path = self::normalizePath($path ?: '/');

        if (is_array($query)) {
            $qStr = self::canonicalQuery($query);
        } else {
            parse_str((string) $query, $qArr);
            $qStr = self::canonicalQuery(is_array($qArr) ? $qArr : []);
        }

        // 4. Load Kunci
        $hmacRaw = null;
        $aeadB64 = null;
        $ed25519PubB64 = null;
        if ($this->keyLoader) {
            $keys = (array) call_user_func($this->keyLoader, $cid, $kid);
            $hmacRaw = $keys['hmacSecret'] ?? null;
            $aeadB64 = $keys['aeadKeyB64'] ?? null;
            $ed25519PubB64 = $keys['ed25519PublicKeyB64'] ?? null;
        }

        $result = ['mode' => null, 'bodyPlain' => null, 'json' => null];

        // --- Verifikasi AEAD / BOTH ---
        $aeadAlg = $H[self::upper(self::HX_AEAD_ALG)] ?? '';
        $aeadNonceHdrB64 = $H[self::upper(self::HX_AEAD_NONCE)] ?? '';

        // Mode 'aead' dan 'both' WAJIB terenkripsi. Jika header AEAD hilang atau
        // algoritmanya tidak dikenal, tolak request — JANGAN lewati blok ini diam-diam.
        // Tanpa pengecekan ini, mode 'both' bisa di-downgrade menjadi HMAC-only
        // sehingga server menerima body plaintext (kebocoran jaminan kerahasiaan).
        if (($this->mode === 'aead' || $this->mode === 'both') && $aeadAlg !== self::AEAD_ALG) {
            throw new SecurePayloadException(
                'Mode ' . $this->mode . ' mewajibkan enkripsi AEAD, namun header AEAD tidak ada atau algoritmanya tidak dikenal',
                SecurePayloadException::UNAUTHORIZED
            );
        }

        // Deteksi apakah ini request terenkripsi
        if (($this->mode === 'aead' || $this->mode === 'both') && $aeadAlg === self::AEAD_ALG) {
            $json = json_decode($rawBody, true);
            $blobB64 = is_array($json) ? ($json['__aead_b64'] ?? '') : '';
            if ($blobB64 === '') {
                throw new SecurePayloadException('Payload AEAD tidak ditemukan', SecurePayloadException::BAD_REQUEST);
            }

            $this->ensureSodium();
            $keyRaw = base64_decode($aeadB64 ?? '', true);
            if (!is_string($keyRaw) || strlen($keyRaw) !== 32) {
                $this->emitEvent(self::EVENT_KEY_NOT_FOUND, ['clientId' => $cid, 'keyId' => $kid, 'kind' => 'aead']);
                throw new SecurePayloadException('Kunci AEAD server tidak valid/tersedia', SecurePayloadException::SERVER_ERROR);
            }
            // Derivasi subkey HKDF (no-op bila deriveKeys nonaktif).
            $keyRaw = $this->deriveSubkey($keyRaw, self::KDF_PURPOSE_AEAD_REQ);

            // Hitung ulang nonce yang seharusnya
            $nonceCalc = self::aeadNonceFrom($nonceB64, $method, $path, $qStr);
            $nonceHdr = base64_decode($aeadNonceHdrB64, true) ?: '';

            // Verifikasi integritas nonce (mencegah pemindahan nonce curian ke konteks lain)
            if (!hash_equals($nonceHdr, $nonceCalc)) {
                $this->emitEvent(self::EVENT_NONCE_MISMATCH, ['clientId' => $cid, 'keyId' => $kid]);
                throw new SecurePayloadException('Nonce mismatch (Integritas request invalid)', SecurePayloadException::UNAUTHORIZED);
            }

            $ct = base64_decode($blobB64, true);
            if ($ct === false) {
                throw new SecurePayloadException('Format base64 body rusak', SecurePayloadException::BAD_REQUEST);
            }

            // AAD diturunkan dari timestamp request + header kritikal yang diikat.
            // Nilai dibaca dari header request masuk (sumber yang sama yang akan
            // dimanipulasi penyerang), sehingga setiap perubahan menggagalkan dekripsi.
            $boundHeaders = $this->collectBoundHeaders($headers);

            // Dekripsi
            $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $ct,
                $this->aeadAAD($ver, $tsStr, $boundHeaders),
                $nonceCalc,
                $keyRaw
            );

            if ($plain === false) {
                $this->emitEvent(self::EVENT_DECRYPT_FAILED, ['clientId' => $cid, 'keyId' => $kid, 'scope' => 'request']);
                throw new SecurePayloadException('Gagal mendekripsi (Kunci salah atau data rusak)', SecurePayloadException::UNAUTHORIZED);
            }

            $used = ($this->mode === 'both') ? 'BOTH-AEAD' : 'AEAD';
            $result['mode'] = $used;

            if ($this->mode === 'aead') {
                // Selesai jika hanya AEAD
                $result['bodyPlain'] = $plain;
                $result['json'] = json_decode($plain, true);
                return $result;
            }

            // Jika BOTH, hasil dekripsi dipakai sebagai input verifikasi HMAC
            $rawBodyForHmac = $plain;

            // Verifikasi Digest Tambahan untuk integritas plaintext
            $digestHdr = $H[self::upper(self::HX_BODY_DIGEST)] ?? '';
            $calc = 'sha256=' . self::bodyDigestB64($rawBodyForHmac);
            if ($digestHdr !== $calc) {
                throw new SecurePayloadException('Integritas Body Digest gagal', SecurePayloadException::UNPROCESSABLE, ['expected' => $calc, 'got' => $digestHdr]);
            }
        }

        // --- Verifikasi Tanda Tangan (HMAC / Ed25519) untuk mode hmac / both ---
        if ($this->mode === 'hmac' || $this->mode === 'both') {
            $alg = $H[self::upper(self::HX_SIG_ALG)] ?? '';
            $sigIn = $H[self::upper(self::HX_SIGNATURE)] ?? '';
            $digH = $H[self::upper(self::HX_BODY_DIGEST)] ?? '';

            // Algoritma ditentukan oleh konfigurasi server (signAlg), BUKAN oleh header.
            // Header yang tidak cocok ditolak untuk mencegah downgrade tanda tangan.
            $expectedAlg = $this->signAlg === 'ed25519' ? self::ED25519_ALG : self::HMAC_ALG;
            if ($alg !== $expectedAlg || $sigIn === '' || $digH === '') {
                throw new SecurePayloadException('Header tanda tangan tidak lengkap/salah algoritma', SecurePayloadException::BAD_REQUEST, ['terima' => $alg, 'ekspektasi' => $expectedAlg]);
            }

            $digHVal = str_starts_with($digH, 'sha256=') ? substr($digH, 7) : '';
            if ($digHVal === '') {
                throw new SecurePayloadException('Format digest salah (harus sha256=...)', SecurePayloadException::BAD_REQUEST);
            }

            // Gunakan plaintext hasil dekripsi (jika ada) atau raw body asli
            $bodyForHmac = isset($rawBodyForHmac) ? $rawBodyForHmac : $rawBody;

            // 1. Verifikasi Hash Body
            $calcDig = self::bodyDigestB64($bodyForHmac);
            if (!hash_equals($digHVal, $calcDig)) {
                throw new SecurePayloadException('Integritas Body Digest HMAC gagal', SecurePayloadException::UNPROCESSABLE);
            }

            // 2. Verifikasi Signature sesuai algoritma
            $msg = self::hmacMessage($this->version, $cid, $kid, $tsStr, $nonceB64, $method, $path, $qStr, $calcDig);

            if ($this->signAlg === 'ed25519') {
                $this->ensureSodium();
                $pub = base64_decode($ed25519PubB64 ?? '', true);
                if (!is_string($pub) || strlen($pub) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                    $this->emitEvent(self::EVENT_KEY_NOT_FOUND, ['clientId' => $cid, 'keyId' => $kid, 'kind' => 'ed25519_public']);
                    throw new SecurePayloadException('Public key Ed25519 server tidak valid/tersedia', SecurePayloadException::SERVER_ERROR);
                }
                $sigRaw = base64_decode($sigIn, true);
                if (!is_string($sigRaw) || strlen($sigRaw) !== SODIUM_CRYPTO_SIGN_BYTES) {
                    throw new SecurePayloadException('Format signature Ed25519 rusak', SecurePayloadException::BAD_REQUEST);
                }
                if (!sodium_crypto_sign_verify_detached($sigRaw, $msg, $pub)) {
                    $this->emitEvent(self::EVENT_SIGNATURE_INVALID, ['clientId' => $cid, 'keyId' => $kid, 'alg' => 'ed25519']);
                    throw new SecurePayloadException('Tanda Tangan (Ed25519) tidak valid', SecurePayloadException::UNAUTHORIZED);
                }
            } else {
                if ($hmacRaw !== null && strlen($hmacRaw) < 32) {
                    throw new SecurePayloadException(
                        'HMAC Secret yang dimuat dari keyLoader terlalu pendek (minimum 32 karakter).',
                        SecurePayloadException::SERVER_ERROR
                    );
                }
                if (!$hmacRaw) {
                    $this->emitEvent(self::EVENT_KEY_NOT_FOUND, ['clientId' => $cid, 'keyId' => $kid, 'kind' => 'hmac']);
                    throw new SecurePayloadException('Secret Key HMAC tidak ditemukan di server', SecurePayloadException::SERVER_ERROR);
                }
                $signKey = $this->deriveSubkey((string) $hmacRaw, self::KDF_PURPOSE_SIGN_REQ);
                $sigB64 = base64_encode(hash_hmac('sha256', $msg, $signKey, true));
                if (!hash_equals($sigB64, $sigIn)) {
                    $this->emitEvent(self::EVENT_SIGNATURE_INVALID, ['clientId' => $cid, 'keyId' => $kid, 'alg' => 'hmac']);
                    throw new SecurePayloadException('Tanda Tangan (Signature) tidak valid', SecurePayloadException::UNAUTHORIZED);
                }
            }

            $result['mode'] = ($this->mode === 'both' && isset($rawBodyForHmac)) ? 'BOTH' : 'HMAC';
            $result['bodyPlain'] = $bodyForHmac;
            $result['json'] = json_decode($bodyForHmac, true);
            return $result;
        }

        throw new SecurePayloadException('Tidak ditemukan header keamanan yang valid', SecurePayloadException::BAD_REQUEST);
    }

    /**
     * Helper Verifikasi Sederhana (Deprecated Behavior Fixed).
     * 
     * PERINGATAN: Fungsi ini telah diperbarui untuk keamanan. 
     * Versi sebelumnya membaca Method dan Path dari header, yang tidak aman.
     * Sekarang Anda WAJIB menyediakannya secara eksplisit.
     *
     * @param array<string,string> $headers
     * @param string $rawBody
     * @param string $method
     * @param string $path
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
     * Fungsi ini adalah wrapper lengkap untuk memvalidasi request yang mengandung file.
     * Melakukan urutan verifikasi sebagai berikut:
     * 1. Verifikasi Signature/Enkripsi menggunakan `verifySimple` (HMAC/AEAD).
     * 2. Pengecekan keberadaan lampiran file dalam payload.
     * 3. Validasi ukuran file (`max_size`).
     * 4. Validasi ekstensi file (`allowed_exts` & `block_dangerous`).
     * 5. Validasi keamanan konten mendalam (`strict_mime`) untuk mencegah spoofing
     *    (misal: file .php yang di-rename menjadi .jpg).
     *
     * @param array  $headers   Array header dari request (gunakan `getallheaders()`).
     * @param string $rawBody   String body mentah dari request (gunakan `file_get_contents('php://input')`).
     * @param string $method    HTTP Method yang diterima server.
     * @param string $path      URL Path yang diterima server.
     * @param array  $constraints {
     *     Opsi konfigurasi pembatasan file:
     *     @type int $max_size
     *          Batas maksimum ukuran file dalam byte. Default: 5242880 (5MB).
     *          
     *     @type string[] $allowed_exts
     *          Daftar ekstensi yang DIZINKAN (Whitelist). 
     *          Jika diisi, hanya file dengan ekstensi ini yang diterima.
     *          Contoh: ['jpg', 'png', 'pdf']. Default: [] (Semua diizinkan kecuali yang berbahaya).
     *          
     *     @type bool|string[] $block_dangerous
     *          Konfigurasi pemblokiran ekstensi berbahaya (Blacklist).
     *          - `true` (Default): Memblokir ekstensi berbahaya standar (php, exe, sh, dll).
     *          - `false`: MENONAKTIFKAN proteksi blacklist (Sangat tidak disarankan).
     *          - `array`: Menambahkan ekstensi kustom ke daftar blokir standar.
     *            Contoh: ['xyz', 'bat'] akan memblokir .xyz, .bat, DAN .php, .exe, dll.
     *            
     *     @type bool $strict_mime
     *          Mengaktifkan pengecekan Mime-Type ketat (Deep Scan).
     *          Jika `true` (Default), library akan membaca magic bytes file asli untuk memastikan
     *          kontennya sesuai dengan ekstensinya (Anti-Spoofing).
     * }
     *
     * @return array{
     *   ok: bool,
     *   file: ?array{name:string, size:int, type:string, content_b64:string, content_decoded:string},
     *   data: mixed,
     *   error?: string,
     *   status?: int
     * }
     * Mengembalikan array hasil. Jika `ok` = true, file dapat diakses di key `file`.
     */
    public function verifyFilePayload(array $headers, string $rawBody, string $method, string $path, array $constraints = []): array
    {
        // 1. Verifikasi Keamanan Dasar (Signature/Encryption)
        $res = $this->verifySimple($headers, $rawBody, $method, $path);
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
                'data' => $data
            ];
        }

        // 2. Validasi Metadata File
        $name = basename((string) ($attachment['name'] ?? 'unknown'));
        $size = (int) ($attachment['size'] ?? 0);
        $contentB64 = $attachment['content'] ?? '';

        // Constraint Defaults
        $maxSize = $constraints['max_size'] ?? 5 * 1024 * 1024; // 5MB

        // Cek Ukuran
        if ($size > $maxSize) {
            return [
                'ok' => false,
                'status' => 413, // Payload Too Large
                'error' => "Ukuran file ($size bytes) melebihi batas ($maxSize bytes)",
                'file' => null,
                'data' => $data
            ];
        }

        // Cek Ekstensi (allow/block list dipakai bersama jalur streaming).
        $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
        $extErr = self::fileExtensionError($ext, $constraints);
        if ($extErr !== null) {
            return ['ok' => false, 'status' => $extErr[0], 'error' => $extErr[1], 'file' => null, 'data' => $data];
        }

        // 3. Decode Content
        $decoded = base64_decode($contentB64, true);
        if ($decoded === false) {
            return [
                'ok' => false,
                'status' => 400,
                'error' => "Gagal decode konten file",
                'file' => null,
                'data' => $data
            ];
        }

        // Double Check Size Integrity
        if (strlen($decoded) !== $size) {
            return [
                'ok' => false,
                'status' => 400,
                'error' => "Integritas ukuran file tidak valid",
                'file' => null,
                'data' => $data
            ];
        }

        // 4. Strict MIME Type & Security Verification (Deep Scan) — anti-spoofing.
        // Sniffing magic-byte konten asli; logika dibagi dengan jalur streaming.
        $strict = $constraints['strict_mime'] ?? true; // Default TRUE for full security
        $mimeErr = self::fileMimeError($decoded, $ext, (bool) $strict);
        if ($mimeErr !== null) {
            return ['ok' => false, 'status' => $mimeErr[0], 'error' => $mimeErr[1], 'file' => null, 'data' => $data];
        }

        return [
            'ok' => true,
            'status' => 200,
            'file' => [
                'name' => $name,
                'size' => $size,
                'type' => $attachment['type'] ?? 'application/octet-stream',
                'content_b64' => $contentB64,
                'content_decoded' => $decoded
            ],
            'data' => $data
        ];
    }

    // --- Validasi keamanan file (dibagi antara payload base64 & streaming) ---

    /**
     * Daftar ekstensi berbahaya bawaan (lowercase).
     *
     * @return list<string>
     */
    private static function dangerousExtList(): array
    {
        return ['php', 'php5', 'phtml', 'exe', 'dll', 'sh', 'bat', 'cmd', 'js', 'vbs', 'python', 'pl', 'cgi'];
    }

    /**
     * Map ekstensi → daftar MIME yang dianggap konsisten (anti-spoofing).
     *
     * @return array<string,list<string>>
     */
    private static function safeMimeMap(): array
    {
        return [
            'jpg' => ['image/jpeg', 'image/pjpeg'],
            'jpeg' => ['image/jpeg', 'image/pjpeg'],
            'png' => ['image/png'],
            'gif' => ['image/gif'],
            'webp' => ['image/webp'],
            'pdf' => ['application/pdf'],
            'txt' => ['text/plain'],
            'json' => ['application/json', 'text/plain'],
            'zip' => ['application/zip'],
            'doc' => ['application/msword'],
            'docx' => ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
            'xls' => ['application/vnd.ms-excel'],
            'xlsx' => ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
        ];
    }

    /**
     * MIME yang selalu diblokir apa pun ekstensinya (executable/script).
     *
     * @return list<string>
     */
    private static function dangerousMimeList(): array
    {
        return [
            'application/x-dosexec',
            'application/x-executable',
            'text/x-php',
            'application/x-php',
            'application/x-httpd-php',
            'text/x-shellscript',
        ];
    }

    /**
     * Validasi ekstensi terhadap allow-list & block-list (logika `block_dangerous`).
     *
     * @param array<string,mixed> $constraints
     * @return array{0:int,1:string}|null Tuple [status, pesan error] atau null bila lolos.
     */
    private static function fileExtensionError(string $ext, array $constraints): ?array
    {
        $blockVal = $constraints['block_dangerous'] ?? true;
        $dangerous = self::dangerousExtList();
        $shouldBlock = false;

        if (is_array($blockVal)) {
            // Blokir default + tambahan kustom.
            foreach ($blockVal as $b) {
                if (is_string($b)) {
                    $dangerous[] = $b;
                }
            }
            $shouldBlock = true;
        } elseif ($blockVal === true) {
            $shouldBlock = true;
        }

        $dangerous = array_map('strtolower', $dangerous);
        if ($shouldBlock && in_array($ext, $dangerous, true)) {
            return [422, "Ekstensi file berbahaya dideteksi (.$ext)"];
        }

        $allowedExts = $constraints['allowed_exts'] ?? [];
        if (is_array($allowedExts) && $allowedExts !== [] && !in_array($ext, array_map('strtolower', $allowedExts), true)) {
            return [422, "Ekstensi file tidak diizinkan (.$ext)"];
        }

        return null;
    }

    /**
     * Validasi MIME hasil sniffing (magic-byte) terhadap ekstensi + blokir MIME berbahaya.
     *
     * @param string $sniffBuffer Cukup beberapa byte awal file (header magic).
     * @return array{0:int,1:string}|null Tuple [status, pesan error] atau null bila lolos.
     */
    private static function fileMimeError(string $sniffBuffer, string $ext, bool $strict): ?array
    {
        if (!$strict) {
            return null;
        }
        $finfo = new \finfo(FILEINFO_MIME_TYPE);
        $realMime = $finfo->buffer($sniffBuffer) ?: 'application/octet-stream';

        $map = self::safeMimeMap();
        if (isset($map[$ext]) && !in_array($realMime, $map[$ext], true)) {
            return [422, "Security Alert: Isi file terdeteksi sebagai '$realMime' namun ekstensi adalah '.$ext'. (Spoofing Detected)"];
        }

        if (in_array($realMime, self::dangerousMimeList(), true)) {
            return [422, "Security Alert: Konten file terdeteksi berbahaya ($realMime)"];
        }

        return null;
    }

    /**
     * Membangun Transfer File Streaming Terenkripsi (Client-Side, Phase 6).
     *
     * Mengenkripsi file per-chunk memakai XChaCha20-Poly1305 *secretstream* tanpa
     * memuat seluruh file ke memori (cocok untuk file besar). Ciphertext ditulis
     * ke `$destPath` (di-frame per-chunk), dan dikembalikan sebuah **manifest**
     * kecil berisi metadata + header secretstream + digest ciphertext.
     *
     * Manifest WAJIB dikirim melalui jalur request biasa (`buildHeadersAndBody()`/
     * `send()`) agar ikut ditandatangani; file ciphertext dikirim terpisah
     * (mis. multipart). Server memverifikasi manifest, lalu memanggil
     * `verifyFileStream()` dengan file ciphertext + manifest.
     *
     * Kunci stream diturunkan dari AEAD key instance (lihat opsi `deriveKeys`),
     * jadi `aeadKeyB64` wajib tersedia.
     *
     * @param string $srcPath   Path file sumber (plaintext).
     * @param string $destPath  Path tujuan untuk menulis ciphertext.
     * @param array{name?:string} $meta Metadata opsional (mis. nama file logis).
     * @param int    $chunkSize Ukuran chunk plaintext per langkah (byte). Default 64 KiB.
     *
     * @return array<string,mixed> Manifest (siap di-JSON-kan & ditandatangani).
     * @throws SecurePayloadException Jika sodium tidak ada, file tak terbaca, atau parameter salah.
     */
    public function buildFileStream(string $srcPath, string $destPath, array $meta = [], int $chunkSize = 65536): array
    {
        $this->ensureSodium();

        if ($chunkSize < 1024 || $chunkSize > self::STREAM_MAX_CHUNK) {
            throw new SecurePayloadException('chunkSize di luar rentang wajar (1KiB–8MiB)', SecurePayloadException::BAD_REQUEST, ['chunkSize' => $chunkSize]);
        }
        if (!is_file($srcPath) || !is_readable($srcPath)) {
            throw new SecurePayloadException("File sumber tidak ditemukan/terbaca: $srcPath", SecurePayloadException::BAD_REQUEST);
        }

        $key = $this->deriveSubkey($this->getAeadKeyRaw(), self::KDF_PURPOSE_AEAD_STREAM);
        $ad = self::streamAAD($this->version);

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
                'v' => $this->version,
                'alg' => self::STREAM_ALG,
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
     * Mendekripsi ciphertext `$encPath` per-chunk ke `$destPath`, sambil:
     *  - memverifikasi setiap chunk via tag Poly1305 secretstream,
     *  - menolak truncation/append (penanda akhir TAG_FINAL wajib & tunggal),
     *  - mencocokkan digest ciphertext terhadap manifest (yang sudah ditandatangani),
     *  - menegakkan batas ukuran, allow/block ekstensi, dan `strict_mime` (sniff
     *    chunk pertama yang sudah didekripsi).
     *
     * GAGAL-TERTUTUP: bila verifikasi gagal di tahap mana pun, file plaintext
     * parsial di `$destPath` DIHAPUS agar tidak menyisakan data tak terverifikasi.
     *
     * @param string $encPath   Path file ciphertext yang diterima.
     * @param array<string,mixed> $manifest Manifest hasil buildFileStream (sudah diverifikasi via jalur request).
     * @param string $destPath  Path tujuan untuk menulis plaintext hasil dekripsi.
     * @param array<string,mixed> $constraints Sama seperti verifyFilePayload (max_size, allowed_exts, block_dangerous, strict_mime).
     *
     * @return array{ok:bool, status:int, error?:string, file?:array{name:string,size:int,type:string,path:string}}
     */
    public function verifyFileStream(string $encPath, array $manifest, string $destPath, array $constraints = []): array
    {
        $in = null;
        $out = null;
        try {
            $this->ensureSodium();

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
            $extErr = self::fileExtensionError($ext, $constraints);
            if ($extErr !== null) {
                return ['ok' => false, 'status' => $extErr[0], 'error' => $extErr[1]];
            }

            if (!is_file($encPath) || !is_readable($encPath)) {
                return ['ok' => false, 'status' => 400, 'error' => "File terenkripsi tidak ditemukan/terbaca: $encPath"];
            }

            $key = $this->deriveSubkey($this->getAeadKeyRaw(), self::KDF_PURPOSE_AEAD_STREAM);
            $ad = self::streamAAD((string) ($manifest['v'] ?? $this->version));

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
            $maxFrame = self::STREAM_MAX_CHUNK + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

            while (true) {
                $lenRaw = self::freadExact($in, 4);
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
                $cipher = self::freadExact($in, $len);
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
            $mimeErr = self::fileMimeError($firstSniff, $ext, $strict);
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
     * AAD konstan untuk secretstream, diikat ke versi protokol.
     */
    private static function streamAAD(string $version): string
    {
        return 'sp-stream-v' . $version;
    }

    /**
     * Baca tepat $len byte (loop sampai cukup atau EOF).
     *
     * @param resource $fh
     */
    private static function freadExact($fh, int $len): string
    {
        $buf = '';
        while (strlen($buf) < $len && !feof($fh)) {
            $r = fread($fh, $len - strlen($buf));
            if ($r === false || $r === '') {
                break;
            }
            $buf .= $r;
        }
        return $buf;
    }

    /**
     * Tutup handle stream dan (opsional) hapus file plaintext parsial saat gagal.
     *
     * @param resource|false|null $in
     * @param resource|false|null $out
     */
    private function streamCleanup($in, $out, string $destPath, bool $removeDest): void
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
     * Membangun Response Aman (Server-Side).
     *
     * Kebalikan dari request: server menandatangani/mengenkripsi, client memverifikasi.
     * Response diikat ke nonce request asal (`X-Nonce`) sehingga tidak bisa dipindah
     * (replay/relocation) ke konteks request lain.
     *
     * Catatan kunci: tanda tangan response SELALU memakai HMAC-SHA256 dengan secret
     * bersama (bukan Ed25519), karena server tidak memegang private key client.
     * Pada mode aead/both, autentisitas response dijamin oleh AEAD tag.
     *
     * @param array<string,string> $requestHeaders Header request masuk (untuk ambil clientId/keyId/nonce).
     * @param array<mixed>          $payload        Data response.
     *
     * @return array{0: array<string,string>, 1: string} Tuple [Headers response, Body string]
     * @throws SecurePayloadException Jika kredensial/kunci tidak tersedia atau enkripsi gagal.
     */
    public function buildResponse(array $requestHeaders, array $payload): array
    {
        // Normalisasi header request untuk pencarian case-insensitive.
        $H = [];
        foreach ($requestHeaders as $k => $v) {
            if (!is_string($k)) {
                continue;
            }
            $H[strtoupper($k)] = (string) $v;
        }

        $cid = $H[self::upper(self::HX_CLIENT_ID)] ?? '';
        $kid = $H[self::upper(self::HX_KEY_ID)] ?? '';
        $reqNonceB64 = $H[self::upper(self::HX_NONCE)] ?? '';
        if ($reqNonceB64 === '') {
            throw new SecurePayloadException('Nonce request tidak ditemukan untuk binding response', SecurePayloadException::BAD_REQUEST);
        }

        // Muat kunci response (server memakai keyLoader; fallback ke kunci instance).
        [$hmacRaw, $aeadB64] = $this->resolveResponseKeys($cid, $kid);

        $ver = $this->version;
        $respTs = (string) time();
        $respNonceB64 = self::genNonceB64();

        $headers = [
            self::HX_RESP_TIMESTAMP => $respTs,
            self::HX_RESP_NONCE => $respNonceB64,
            self::HX_RESP_SIG_VER => $ver,
        ];

        $plain = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($plain === false) {
            throw new SecurePayloadException('Gagal encode JSON response', SecurePayloadException::BAD_REQUEST);
        }

        // --- Enkripsi (mode aead / both) ---
        $bodyOut = $plain;
        if ($this->mode === 'aead' || $this->mode === 'both') {
            $this->ensureSodium();
            $keyRaw = base64_decode($aeadB64 ?? '', true);
            if (!is_string($keyRaw) || strlen($keyRaw) !== 32) {
                throw new SecurePayloadException('Kunci AEAD response tidak valid/tersedia', SecurePayloadException::SERVER_ERROR);
            }
            $keyRaw = $this->deriveSubkey($keyRaw, self::KDF_PURPOSE_AEAD_RESP);
            $aeadNonce = self::respAeadNonceFrom($respNonceB64, $reqNonceB64);
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $plain,
                $this->respAeadAAD($ver, $reqNonceB64, $respTs),
                $aeadNonce,
                $keyRaw
            );
            $bodyOut = json_encode(['__aead_b64' => base64_encode($ciphertext)], JSON_UNESCAPED_SLASHES);
            $headers[self::HX_RESP_AEAD_ALG] = self::AEAD_ALG;
            $headers[self::HX_RESP_AEAD_NONCE] = base64_encode($aeadNonce);
        }

        // --- Tanda Tangan (mode hmac / both) ---
        if ($this->mode === 'hmac' || $this->mode === 'both') {
            if ($hmacRaw === null || $hmacRaw === '') {
                throw new SecurePayloadException('Secret Key HMAC response tidak tersedia di server', SecurePayloadException::SERVER_ERROR);
            }
            if (strlen($hmacRaw) < 32) {
                throw new SecurePayloadException('HMAC Secret response terlalu pendek (minimum 32 karakter)', SecurePayloadException::SERVER_ERROR);
            }
            // Tanda tangan dibuat atas plaintext (sama seperti jalur request mode both).
            $digestB64 = self::bodyDigestB64($plain);
            $msg = self::respMessage($ver, $reqNonceB64, $respTs, $respNonceB64, $digestB64);
            $signKey = $this->deriveSubkey($hmacRaw, self::KDF_PURPOSE_SIGN_RESP);
            $sigB64 = base64_encode(hash_hmac('sha256', $msg, $signKey, true));
            $headers[self::HX_RESP_SIG_ALG] = self::HMAC_ALG;
            $headers[self::HX_RESP_BODY_DIGEST] = 'sha256=' . $digestB64;
            $headers[self::HX_RESP_SIGNATURE] = $sigB64;
        }

        return [$headers, $bodyOut];
    }

    /**
     * Verifikasi Response Aman (Client-Side) — aman, tanpa Exception.
     *
     * @param array<string,string> $headers      Header response dari server.
     * @param string               $rawBody      Body mentah response.
     * @param string               $reqNonceB64  Nonce request asal (nilai header X-Nonce yang dikirim client).
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
     * @param array<string,string> $headers
     * @param string               $rawBody
     * @param string               $reqNonceB64
     *
     * @return array{mode:string, bodyPlain:string|null, json:mixed}
     * @throws SecurePayloadException Jika verifikasi gagal.
     */
    public function verifyResponseOrThrow(array $headers, string $rawBody, string $reqNonceB64): array
    {
        if ($reqNonceB64 === '') {
            throw new SecurePayloadException('Nonce request asal wajib diisi untuk verifikasi response', SecurePayloadException::BAD_REQUEST);
        }

        $H = [];
        foreach ($headers as $k => $v) {
            if (!is_string($k)) {
                continue;
            }
            $H[strtoupper($k)] = (string) $v;
        }

        $ver = $H[self::upper(self::HX_RESP_SIG_VER)] ?? '';
        $respTs = $H[self::upper(self::HX_RESP_TIMESTAMP)] ?? '';
        $respNonceB64 = $H[self::upper(self::HX_RESP_NONCE)] ?? '';

        if ($ver === '' || $respTs === '' || $respNonceB64 === '') {
            throw new SecurePayloadException('Header response tidak lengkap', SecurePayloadException::BAD_REQUEST);
        }
        if ($ver !== $this->version) {
            throw new SecurePayloadException('Versi protokol response tidak didukung', SecurePayloadException::BAD_REQUEST, ['terima' => $ver, 'ekspektasi' => $this->version]);
        }

        // Validasi kesegaran timestamp response (mencegah response usang diputar ulang).
        if (!preg_match('/^\d+$/', $respTs)) {
            throw new SecurePayloadException('Format timestamp response salah', SecurePayloadException::BAD_REQUEST, ['nilai' => $respTs]);
        }
        $ts = (int) $respTs;
        $now = time();
        if ($ts > $now + $this->clockSkew || $ts < $now - ($this->replayTtl + $this->clockSkew)) {
            throw new SecurePayloadException('Timestamp response di luar batas wajar', SecurePayloadException::UNAUTHORIZED, ['ts' => $ts, 'now' => $now]);
        }

        $result = ['mode' => null, 'bodyPlain' => null, 'json' => null];

        $aeadAlg = $H[self::upper(self::HX_RESP_AEAD_ALG)] ?? '';
        $aeadNonceHdrB64 = $H[self::upper(self::HX_RESP_AEAD_NONCE)] ?? '';

        // Mode aead/both: response WAJIB terenkripsi (anti-downgrade, sama seperti request).
        if (($this->mode === 'aead' || $this->mode === 'both') && $aeadAlg !== self::AEAD_ALG) {
            throw new SecurePayloadException(
                'Mode ' . $this->mode . ' mewajibkan enkripsi AEAD pada response, namun header AEAD tidak ada/tidak dikenal',
                SecurePayloadException::UNAUTHORIZED
            );
        }

        $bodyForSig = $rawBody;

        if (($this->mode === 'aead' || $this->mode === 'both') && $aeadAlg === self::AEAD_ALG) {
            $json = json_decode($rawBody, true);
            $blobB64 = is_array($json) ? ($json['__aead_b64'] ?? '') : '';
            if ($blobB64 === '') {
                throw new SecurePayloadException('Payload AEAD response tidak ditemukan', SecurePayloadException::BAD_REQUEST);
            }

            $this->ensureSodium();
            $keyRaw = base64_decode($this->aeadKeyB64 ?? '', true);
            if (!is_string($keyRaw) || strlen($keyRaw) !== 32) {
                throw new SecurePayloadException('Kunci AEAD client tidak valid/tersedia', SecurePayloadException::BAD_REQUEST);
            }
            $keyRaw = $this->deriveSubkey($keyRaw, self::KDF_PURPOSE_AEAD_RESP);

            $nonceCalc = self::respAeadNonceFrom($respNonceB64, $reqNonceB64);
            $nonceHdr = base64_decode($aeadNonceHdrB64, true) ?: '';
            if (!hash_equals($nonceHdr, $nonceCalc)) {
                throw new SecurePayloadException('Nonce response mismatch (integritas invalid)', SecurePayloadException::UNAUTHORIZED);
            }

            $ct = base64_decode($blobB64, true);
            if ($ct === false) {
                throw new SecurePayloadException('Format base64 body response rusak', SecurePayloadException::BAD_REQUEST);
            }

            $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $ct,
                $this->respAeadAAD($ver, $reqNonceB64, $respTs),
                $nonceCalc,
                $keyRaw
            );
            if ($plain === false) {
                throw new SecurePayloadException('Gagal mendekripsi response (kunci salah atau data rusak)', SecurePayloadException::UNAUTHORIZED);
            }

            if ($this->mode === 'aead') {
                $result['mode'] = 'AEAD';
                $result['bodyPlain'] = $plain;
                $result['json'] = json_decode($plain, true);
                return $result;
            }
            // Mode both: plaintext hasil dekripsi dipakai untuk verifikasi HMAC.
            $bodyForSig = $plain;
        }

        // --- Verifikasi Tanda Tangan HMAC (mode hmac / both) ---
        if ($this->mode === 'hmac' || $this->mode === 'both') {
            $alg = $H[self::upper(self::HX_RESP_SIG_ALG)] ?? '';
            $sigIn = $H[self::upper(self::HX_RESP_SIGNATURE)] ?? '';
            $digH = $H[self::upper(self::HX_RESP_BODY_DIGEST)] ?? '';

            if ($alg !== self::HMAC_ALG || $sigIn === '' || $digH === '') {
                throw new SecurePayloadException('Header tanda tangan response tidak lengkap/salah algoritma', SecurePayloadException::BAD_REQUEST);
            }
            $digHVal = str_starts_with($digH, 'sha256=') ? substr($digH, 7) : '';
            if ($digHVal === '') {
                throw new SecurePayloadException('Format digest response salah (harus sha256=...)', SecurePayloadException::BAD_REQUEST);
            }

            $calcDig = self::bodyDigestB64($bodyForSig);
            if (!hash_equals($digHVal, $calcDig)) {
                throw new SecurePayloadException('Integritas Body Digest response gagal', SecurePayloadException::UNPROCESSABLE);
            }

            $hmacRaw = $this->hmacSecretRaw;
            if ($hmacRaw === null || $hmacRaw === '') {
                throw new SecurePayloadException('Secret Key HMAC response tidak tersedia di client', SecurePayloadException::BAD_REQUEST);
            }

            $msg = self::respMessage($this->version, $reqNonceB64, $respTs, $respNonceB64, $calcDig);
            $signKey = $this->deriveSubkey($hmacRaw, self::KDF_PURPOSE_SIGN_RESP);
            $sigB64 = base64_encode(hash_hmac('sha256', $msg, $signKey, true));
            if (!hash_equals($sigB64, $sigIn)) {
                throw new SecurePayloadException('Tanda Tangan response tidak valid', SecurePayloadException::UNAUTHORIZED);
            }

            $result['mode'] = ($this->mode === 'both') ? 'BOTH' : 'HMAC';
            $result['bodyPlain'] = $bodyForSig;
            $result['json'] = json_decode($bodyForSig, true);
            return $result;
        }

        throw new SecurePayloadException('Tidak ditemukan header keamanan response yang valid', SecurePayloadException::BAD_REQUEST);
    }

    /**
     * Menyelesaikan kunci untuk membangun response di sisi server.
     * Mengutamakan keyLoader (multi-client); fallback ke kunci instance.
     *
     * @return array{0:?string,1:?string} Tuple [hmacSecret, aeadKeyB64]
     */
    private function resolveResponseKeys(string $cid, string $kid): array
    {
        if ($this->keyLoader) {
            $keys = (array) call_user_func($this->keyLoader, $cid, $kid);
            return [$keys['hmacSecret'] ?? null, $keys['aeadKeyB64'] ?? null];
        }
        return [$this->hmacSecretRaw, $this->aeadKeyB64];
    }

    // --- Private & Internal Helpers ---

    /**
     * Emit event keamanan ke hook `onSecurityEvent` bila terpasang.
     *
     * Murni observasional. Exception apa pun dari callback ditelan agar tidak
     * pernah mengubah hasil/keamanan verifikasi. Pemanggil WAJIB hanya mengisi
     * $context dengan data non-rahasia (clientId/keyId/alasan/timestamp) — tidak
     * pernah secret, plaintext, atau ciphertext.
     *
     * @param array<string,mixed> $context
     */
    private function emitEvent(string $event, array $context = []): void
    {
        if ($this->onSecurityEvent === null) {
            return;
        }
        try {
            call_user_func($this->onSecurityEvent, $event, $context);
        } catch (\Throwable $e) {
            // Sengaja diabaikan: observability tidak boleh memengaruhi verifikasi.
        }
    }

    private function checkReplay(string $cid, string $kid, string $tsStr, string $nonceB64): void
    {
        // Sebuah nonce harus "diingat" selama request yang membawanya masih bisa
        // dianggap segar oleh validasi timestamp, yaitu replayTtl + clockSkew.
        // Jika hanya replayTtl, ada celah waktu di mana nonce sudah dilupakan
        // namun timestamp masih valid sehingga replay (dengan ts dimutasi) lolos.
        $memoryTtl = $this->replayTtl + $this->clockSkew;

        // Probabilistic Garbage Collection: ~0.2% chance per request
        // Wajib gunakan $replayStore kustom (Redis/Memcached) di lingkungan produksi.
        if (random_int(1, 500) === 1) {
            $this->cleanupNonceFiles();
        }

        // PENTING: timestamp TIDAK dimasukkan ke dalam kunci replay. Sebuah nonce
        // wajib sekali-pakai terlepas dari nilai timestamp. Pada mode 'aead'
        // timestamp tidak ditandatangani/terotentikasi, sehingga jika ts ikut
        // menjadi bagian kunci, penyerang cukup mengubah ts untuk memutar ulang
        // request dengan nonce yang sama (replay attack).
        $cacheKey = 'sp_' . substr(hash('sha256', "$cid|$kid|$nonceB64"), 0, 48);

        if ($this->replayStore) {
            $okNew = (bool) call_user_func($this->replayStore, $cacheKey, $memoryTtl);
            if (!$okNew) {
                $this->emitEvent(self::EVENT_REPLAY_DETECTED, ['clientId' => $cid, 'keyId' => $kid, 'source' => 'store']);
                throw new SecurePayloadException('Replay detected (Store)', SecurePayloadException::UNAUTHORIZED);
            }
            return;
        }

        // Fallback file-based replay protection (dengan locking untuk mencegah race condition)
        $dir = sys_get_temp_dir();
        $f = $dir . DIRECTORY_SEPARATOR . $cacheKey;

        // Kita menggunakan file sebagai flag. Jika file ada dan umur < TTL, maka replay.
        // Race condition mitigation: Gunakan 'x' (create only) atau lock.

        // Strategi Sederhana dengan @touch + filemtime check
        // Perhatian: Ini tidak atomic sempurna di semua OS tanpa lock, tapi cukup untuk case moderat.
        // Untuk produksi high-concurrency, WAJIB gunakan Redis/Memcached via $replayStore.

        if (file_exists($f)) {
            $mtime = filemtime($f);
            $age = $mtime !== false ? time() - $mtime : $memoryTtl + 1;
            if ($age < $memoryTtl) {
                $this->emitEvent(self::EVENT_REPLAY_DETECTED, ['clientId' => $cid, 'keyId' => $kid, 'source' => 'file']);
                throw new SecurePayloadException('Replay detected (File)', SecurePayloadException::UNAUTHORIZED, ['age' => $age]);
            }
        }

        // Update timestamp file (atau buat baru)
        // Menggunakan flock untuk memastikan tidak ada dua proses menulis bersamaan
        $fp = fopen($f, 'c+'); // c+ tidak truncate, open buat read/write
        if ($fp) {
            if (flock($fp, LOCK_EX)) { // Exclusive Lock
                // Cek lagi setelah lock didapat (double-checked locking)
                $stat = fstat($fp);
                $age = time() - $stat['mtime'];
                // Jika file sudah ada isinya/ukurannya 0 tapi mtime baru saja, reject? 
                // Di sini kita asumsikan keberadaan file + mtime baru = key sudah terpakai

                // Jika baru saja disentuh oleh proses lain dalam durasi memory TTL
                if ($stat['size'] > 0 && $age < $memoryTtl) {
                    flock($fp, LOCK_UN);
                    fclose($fp);
                    $this->emitEvent(self::EVENT_REPLAY_DETECTED, ['clientId' => $cid, 'keyId' => $kid, 'source' => 'file_locked']);
                    throw new SecurePayloadException('Replay detected (Locked)', SecurePayloadException::UNAUTHORIZED);
                }

                // Tandai terpakai
                ftruncate($fp, 0);
                fwrite($fp, "1"); // Tulis byte agar size > 0
                fflush($fp);
                flock($fp, LOCK_UN);
            }
            fclose($fp);
        } else {
            // Fallback jika gagal open file
            @touch($f);
        }
    }

    /**
     * Membersihkan file nonce cache yang sudah kedaluwarsa di direktori temp.
     * Dipanggil secara probabilistik untuk mencegah storage exhaustion.
     * 
     * @internal
     */
    private function cleanupNonceFiles(): void
    {
        $dir = sys_get_temp_dir();
        $pattern = $dir . DIRECTORY_SEPARATOR . 'sp_*';
        $files = glob($pattern);

        if (!$files) {
            return;
        }

        $cutoff = time() - ($this->replayTtl + $this->clockSkew);

        foreach ($files as $file) {
            if (!is_file($file)) {
                continue;
            }
            $mtime = @filemtime($file);
            if ($mtime !== false && $mtime < $cutoff) {
                @unlink($file);
            }
        }
    }

    /**
     * Menandatangani pesan kanonik sesuai signAlg yang dikonfigurasi (Client-Side).
     *
     * @return array{0:string,1:string} Tuple [signature base64, nama algoritma untuk header]
     */
    private function signCanonical(string $msg): array
    {
        if ($this->signAlg === 'ed25519') {
            $this->ensureSodium();
            $sk = $this->getEd25519SecretKeyRaw();
            $sig = sodium_crypto_sign_detached($msg, $sk);
            return [base64_encode($sig), self::ED25519_ALG];
        }

        $signKey = $this->deriveSubkey((string) $this->hmacSecretRaw, self::KDF_PURPOSE_SIGN_REQ);
        $hmac = hash_hmac('sha256', $msg, $signKey, true);
        return [base64_encode($hmac), self::HMAC_ALG];
    }

    private function getEd25519SecretKeyRaw(): string
    {
        $sk = base64_decode($this->ed25519SecretKeyB64 ?? '', true);
        if (!is_string($sk) || strlen($sk) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new SecurePayloadException(
                'Secret key Ed25519 tidak valid/tersedia (harus base64 dari 64 byte)',
                SecurePayloadException::BAD_REQUEST
            );
        }
        return $sk;
    }

    private function getAeadKeyRaw(): string
    {
        $aeadKeyRaw = base64_decode($this->aeadKeyB64 ?? '', true);
        if (!is_string($aeadKeyRaw) || strlen($aeadKeyRaw) !== 32) {
            throw new SecurePayloadException('Kunci AEAD tidak valid (harus 32 byte base64)', SecurePayloadException::BAD_REQUEST);
        }
        return $aeadKeyRaw;
    }

    /**
     * Turunkan subkey 32-byte dari sebuah master key memakai HKDF-SHA256.
     *
     * Pemisahan domain berbasis parameter `info` (purpose): kunci untuk fungsi
     * berbeda (mis. enkripsi vs signing) tidak akan sama walau master-nya sama,
     * sehingga kebocoran satu subkey tidak otomatis membahayakan fungsi lain.
     *
     * @param string $master  Master key (≥1 byte; HMAC secret raw atau AEAD key raw).
     * @param string $purpose Label fungsi unik (lihat konstanta KDF_PURPOSE_*).
     * @param int    $len     Panjang subkey dalam byte (default 32).
     *
     * @return string Subkey biner sepanjang $len byte.
     * @throws SecurePayloadException Jika master kosong atau derivasi gagal.
     */
    public static function deriveKey(string $master, string $purpose, int $len = 32): string
    {
        if ($master === '') {
            throw new SecurePayloadException('Master key kosong untuk derivasi HKDF', SecurePayloadException::SERVER_ERROR);
        }
        // hash_hkdf melempar ValueError untuk algoritma/panjang tidak valid;
        // dengan sha256 + $len wajar, hasilnya selalu string biner sepanjang $len.
        return hash_hkdf('sha256', $master, $len, $purpose);
    }

    /**
     * Terapkan derivasi subkey HKDF bila opsi `deriveKeys` aktif; jika tidak,
     * kembalikan material apa adanya (kompatibel dengan perilaku lama).
     *
     * Purpose diikat ke versi protokol instance ini, sehingga subkey otomatis
     * berbeda antar versi protokol. Client & server WAJIB memakai konfigurasi
     * (`deriveKeys` + `version`) yang sama agar subkey cocok.
     */
    private function deriveSubkey(string $material, string $purpose): string
    {
        if (!$this->deriveKeys) {
            return $material;
        }
        return self::deriveKey($material, $purpose . '|v' . $this->version);
    }

    private function ensureSodium(): void
    {
        if (!extension_loaded('sodium')) {
            throw new SecurePayloadException('Ekstensi sodium diperlukan untuk mode AEAD/BOTH', SecurePayloadException::SERVER_ERROR);
        }
    }

    private static function upper(string $s): string
    {
        return strtoupper($s);
    }

    /**
     * Normalisasi path URL.
     * Pastikan selalu diawali '/' dan tidak diakhiri '/' (kecuali root).
     */
    public static function normalizePath(string $path): string
    {
        if ($path === '')
            return '/';
        $path = '/' . ltrim($path, '/');
        if (strlen($path) > 1) {
            $path = rtrim($path, '/');
        }
        return $path;
    }

    /**
     * Canonicalisasi Query String.
     * Urutkan key secara ASC, lalu bangun string query ter-encode.
     * @param array<string,mixed> $q
     */
    public static function canonicalQuery(array $q): string
    {
        if (!$q)
            return '';
        ksort($q, SORT_STRING);
        $out = [];
        foreach ($q as $k => $v) {
            if (is_array($v)) {
                // Konvensi: array digabung koma atau abaikan nested kompleks
                $v = implode(',', array_map('strval', $v));
            } else {
                $v = (string) $v;
            }
            $out[] = rawurlencode((string) $k) . '=' . rawurlencode($v);
        }
        return implode('&', $out);
    }

    /** Generate nonce acak 16 byte (Base64). */
    public static function genNonceB64(): string
    {
        return base64_encode(random_bytes(16));
    }

    /** Hitung SHA-256 digest dari string body. */
    public static function bodyDigestB64(string $body): string
    {
        return base64_encode(hash('sha256', $body, true));
    }

    /**
     * Bentuk AAD (Additional Authenticated Data) untuk enkripsi REQUEST.
     *
     * Selain versi protokol, AAD mengikat timestamp request — yang pada mode
     * 'aead' tidak ikut ditandatangani HMAC — sehingga manipulasi X-Timestamp
     * otomatis menggagalkan dekripsi. Header kritikal yang dipilih lewat opsi
     * `bindHeaders` turut diikat. $boundHeaders harus sudah dinormalisasi &
     * diurutkan oleh collectBoundHeaders() agar identik di client & server.
     *
     * @param array<string,string> $boundHeaders Map nama-header(lowercase) => nilai, terurut.
     */
    private function aeadAAD(string $version, string $ts, array $boundHeaders = []): string
    {
        $parts = ['v' . $version, 'ts=' . $ts];
        foreach ($boundHeaders as $name => $val) {
            $parts[] = 'h:' . $name . '=' . $val;
        }
        return implode("\n", $parts);
    }

    /**
     * Kumpulkan nilai header yang diikat ke AAD AEAD.
     *
     * Nama header dinormalisasi ke huruf kecil lalu hasilnya di-`ksort`, agar
     * client & server menghasilkan AAD identik tanpa bergantung pada urutan
     * maupun kapitalisasi header asli. Header yang tidak ada diperlakukan sebagai
     * string kosong — sehingga MENGHAPUS header yang seharusnya ada tetap
     * mengubah AAD (dan menggagalkan dekripsi), bukan diam-diam diabaikan.
     *
     * @param array<string,string> $headers
     * @return array<string,string> Map nama-header(lowercase) => nilai, terurut.
     */
    private function collectBoundHeaders(array $headers): array
    {
        if ($this->bindHeaders === []) {
            return [];
        }
        $norm = [];
        foreach ($headers as $k => $v) {
            if (is_string($k)) {
                $norm[strtolower($k)] = (string) $v;
            }
        }
        $out = [];
        foreach ($this->bindHeaders as $name) {
            $lname = strtolower($name);
            $out[$lname] = $norm[$lname] ?? '';
        }
        ksort($out);
        return $out;
    }

    /**
     * Turunkan AEAD Nonce 24-byte (XChaCha20) yang terikat dengan request context.
     * Mencegah nonce reuse dan memvalidasi binding parameter.
     */
    public static function aeadNonceFrom(string $nonceB64, string $method, string $path, string $qStr): string
    {
        // Seed diambil dari random nonce client
        $seed = base64_decode($nonceB64, true) ?: str_repeat("\0", 16);

        // Campur dengan data request
        $msg = implode("\n", [strtoupper($method), self::normalizePath($path), (string) $qStr, $seed]);

        // Hash jadi 32 byte -> potong sesuai kebutuhan algoritma (biasanya 24 byte untuk XChaCha20)
        $h = hash('sha256', $msg, true);

        $len = defined('SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES')
            ? (int) SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
            : 24;

        return substr($h, 0, $len);
    }

    /**
     * Buat Pesan Kanonik untuk HMAC.
     * Struktur string yang akan ditandatangani. Harus konsisten di Client & Server.
     */
    public static function hmacMessage(string $ver, string $clientId, string $keyId, string $ts, string $nonceB64, string $method, string $path, string $qStr, string $bodyDigestB64): string
    {
        return implode("\n", [
            'v' . $ver,
            'client=' . $clientId,
            'key=' . $keyId,
            'ts=' . $ts,
            'nonce=' . $nonceB64,
            'm=' . $method,
            'p=' . $path,
            'q=' . $qStr,
            'bd=sha256:' . $bodyDigestB64,
            '', // Trailing newline
        ]);
    }

    /**
     * AAD untuk enkripsi RESPONSE. Mengikat versi + nonce request asal +
     * timestamp response, sehingga ciphertext response tidak bisa dipindah ke
     * konteks request lain dan manipulasi X-Resp-Timestamp (tidak ditandatangani
     * HMAC pada mode 'aead') otomatis menggagalkan dekripsi.
     */
    private function respAeadAAD(string $version, string $reqNonceB64, string $respTs): string
    {
        return 'resp-v' . $version . '|req=' . $reqNonceB64 . '|ts=' . $respTs;
    }

    /**
     * Turunkan AEAD Nonce 24-byte untuk RESPONSE, terikat ke nonce response
     * acak dan nonce request asal (binding dua arah).
     */
    public static function respAeadNonceFrom(string $respNonceB64, string $reqNonceB64): string
    {
        $seed = base64_decode($respNonceB64, true) ?: str_repeat("\0", 16);
        $msg = implode("\n", ['response', $reqNonceB64, $seed]);
        $h = hash('sha256', $msg, true);

        $len = defined('SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES')
            ? (int) SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
            : 24;

        return substr($h, 0, $len);
    }

    /**
     * Pesan Kanonik untuk tanda tangan RESPONSE.
     * Mengikat nonce request asal ($reqNonceB64) agar response terikat ke request-nya.
     * Harus konsisten antara server (pembuat) dan client (pemverifikasi).
     */
    public static function respMessage(string $ver, string $reqNonceB64, string $respTs, string $respNonceB64, string $bodyDigestB64): string
    {
        return implode("\n", [
            'resp-v' . $ver,
            'req-nonce=' . $reqNonceB64,
            'resp-ts=' . $respTs,
            'resp-nonce=' . $respNonceB64,
            'bd=sha256:' . $bodyDigestB64,
            '', // Trailing newline
        ]);
    }
}
