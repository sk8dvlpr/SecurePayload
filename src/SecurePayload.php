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

    public const HMAC_ALG = 'HMAC-SHA256';
    public const AEAD_ALG = 'XCHACHA20-POLY1305-IETF';
    public const DEFAULT_VERSION = '1';

    /** @var 'hmac'|'aead'|'both' Mode keamanan yang digunakan */
    private string $mode;

    /** @var string Versi protokol */
    private string $version;

    private ?string $clientId;
    private ?string $keyId;
    private ?string $hmacSecretRaw;
    private ?string $aeadKeyB64;

    /** @var callable(string,string): array{hmacSecret:?string,aeadKeyB64:?string}|null Fungsi untuk memuat kunci */
    private $keyLoader;

    /** @var callable(string,int): bool|null Fungsi kustom untuk penyimpanan replay cache */
    private $replayStore;

    /** @var int Time-to-live untuk replay protection (detik) */
    private int $replayTtl;

    /** @var int Toleransi perbedaan waktu jam server (detik) */
    private int $clockSkew;

    /**
     * Konstruktor SecurePayload
     *
     * Konfigurasi yang didukung dalam $opts:
     * - mode: 'hmac' | 'aead' | 'both' (Default: 'both')
     * - version: Versi protokol (Default: '1')
     * - clientId: ID Client (Wajib untuk mode Client)
     * - keyId: ID Key (Wajib untuk mode Client)
     * - hmacSecretRaw: Secret key untuk HMAC (Raw string)
     * - aeadKeyB64: Secret key untuk AEAD (Base64 string)
     * - keyLoader: Callable untuk memuat kunci di sisi server
     * - replayStore: Callable untuk custom storage replay protection
     * - replayTtl: Durasi validitas nonce dalam detik (Default: 120)
     * - clockSkew: Toleransi perbedaan jam dalam detik (Default: 60)
     *
     * @param array{
     *   mode?: 'hmac'|'aead'|'both',
     *   version?: string,
     *   clientId?: string,
     *   keyId?: string,
     *   hmacSecretRaw?: string|null,
     *   aeadKeyB64?: string|null,
     *   keyLoader?: callable|null,
     *   replayStore?: callable|null,
     *   replayTtl?: int,
     *   clockSkew?: int
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
        $this->aeadKeyB64 = $opts['aeadKeyB64'] ?? null;
        $this->keyLoader = $opts['keyLoader'] ?? null;
        $this->replayStore = $opts['replayStore'] ?? null;
        $this->replayTtl = isset($opts['replayTtl']) ? (int) $opts['replayTtl'] : 120;
        $this->clockSkew = isset($opts['clockSkew']) ? (int) $opts['clockSkew'] : 60;

        if (!in_array($this->mode, ['hmac', 'aead', 'both'], true)) {
            throw new SecurePayloadException('Mode tidak valid: ' . $this->mode, SecurePayloadException::BAD_REQUEST);
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
     * 
     * @return array{0: array<string,string>, 1: string} Tuple [Headers array, Body string]
     * 
     * @throws SecurePayloadException Jika parameter salah atau enkripsi gagal
     */
    public function buildHeadersAndBody(string $url, string $method, array $payload): array
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

        // Header dasar yang selalu ada
        $headers = [
            self::HX_CLIENT_ID => (string) $this->clientId,
            self::HX_KEY_ID => (string) $this->keyId,
            self::HX_TIMESTAMP => $ts,
            self::HX_NONCE => $nonceB64,
            self::HX_SIG_VER => $ver,
                // X-Canonical-Request dikirim sebagai debugging hint, BUKAN source of truth untuk keamanan server
            self::HX_CANON_REQ => base64_encode($method . "\n" . $path . "\n" . $qStr),
        ];

        // --- MODE: AEAD (Enkripsi Saja) ---
        if ($this->mode === 'aead') {
            $body = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if ($body === false) {
                throw new SecurePayloadException('Gagal encode JSON payload', SecurePayloadException::BAD_REQUEST);
            }
            $this->ensureSodium();

            $aeadKeyRaw = $this->getAeadKeyRaw();
            $aeadNonce = self::aeadNonceFrom($nonceB64, $method, $path, $qStr);

            // Enkripsi body
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $body,
                $this->aeadAAD($ver),
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

            $aeadKeyRaw = $this->getAeadKeyRaw();
            $aeadNonce = self::aeadNonceFrom($nonceB64, $method, $path, $qStr);

            // Enkripsi
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $plain,
                $this->aeadAAD($ver),
                $aeadNonce,
                $aeadKeyRaw
            );
            $ctB64 = base64_encode($ciphertext);
            $body = json_encode(['__aead_b64' => $ctB64], JSON_UNESCAPED_SLASHES);

            // Tanda tangan dilakukan terhadap Plaintext asli, bukan ciphertext
            // agar server memverifikasi makna data, bukan bungkusnya.
            $digestB64 = self::bodyDigestB64($plain);
            $msg = self::hmacMessage($ver, (string) $this->clientId, (string) $this->keyId, $ts, $nonceB64, $method, $path, $qStr, $digestB64);
            $hmac = hash_hmac('sha256', $msg, (string) $this->hmacSecretRaw, true);
            $sigB64 = base64_encode($hmac);

            $headers[self::HX_AEAD_ALG] = self::AEAD_ALG;
            $headers[self::HX_AEAD_NONCE] = base64_encode($aeadNonce);
            $headers[self::HX_SIG_ALG] = self::HMAC_ALG;
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
        $hmac = hash_hmac('sha256', $msg, (string) $this->hmacSecretRaw, true);
        $sigB64 = base64_encode($hmac);

        $headers[self::HX_SIG_ALG] = self::HMAC_ALG;
        $headers[self::HX_BODY_DIGEST] = 'sha256=' . $digestB64;
        $headers[self::HX_SIGNATURE] = $sigB64;

        return [$headers, $plain];
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
        if (!extension_loaded('curl')) {
            throw new SecurePayloadException('Ekstensi cURL diperlukan untuk metode send()', SecurePayloadException::SERVER_ERROR);
        }

        [$headers, $body] = $this->buildHeadersAndBody($url, $method, $payload);

        $outHeaders = [];
        foreach (array_merge($headers, $extraHeaders) as $k => $v) {
            $outHeaders[] = $k . ': ' . $v;
        }

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array_merge($outHeaders, ['Content-Type: application/json']));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);

        $resp = curl_exec($ch);
        $err = $resp === false ? curl_error($ch) : null;
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);

        $rawHeaders = substr((string) $resp, 0, $headerSize);
        $bodyStr = substr((string) $resp, $headerSize);
        curl_close($ch);

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
        if ($this->keyLoader) {
            $keys = (array) call_user_func($this->keyLoader, $cid, $kid);
            $hmacRaw = $keys['hmacSecret'] ?? null;
            $aeadB64 = $keys['aeadKeyB64'] ?? null;
        }

        $result = ['mode' => null, 'bodyPlain' => null, 'json' => null];

        // --- Verifikasi AEAD / BOTH ---
        $aeadAlg = $H[self::upper(self::HX_AEAD_ALG)] ?? '';
        $aeadNonceHdrB64 = $H[self::upper(self::HX_AEAD_NONCE)] ?? '';

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
                throw new SecurePayloadException('Kunci AEAD server tidak valid/tersedia', SecurePayloadException::SERVER_ERROR);
            }

            // Hitung ulang nonce yang seharusnya
            $nonceCalc = self::aeadNonceFrom($nonceB64, $method, $path, $qStr);
            $nonceHdr = base64_decode($aeadNonceHdrB64, true) ?: '';

            // Verifikasi integritas nonce (mencegah pemindahan nonce curian ke konteks lain)
            if (!hash_equals($nonceHdr, $nonceCalc)) {
                throw new SecurePayloadException('Nonce mismatch (Integritas request invalid)', SecurePayloadException::UNAUTHORIZED);
            }

            $ct = base64_decode($blobB64, true);
            if ($ct === false) {
                throw new SecurePayloadException('Format base64 body rusak', SecurePayloadException::BAD_REQUEST);
            }

            // Dekripsi
            $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $ct,
                $this->aeadAAD($ver),
                $nonceCalc,
                $keyRaw
            );

            if ($plain === false) {
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

        // --- Verifikasi HMAC / BOTH ---
        if ($this->mode === 'hmac' || $this->mode === 'both') {
            $alg = $H[self::upper(self::HX_SIG_ALG)] ?? '';
            $sigIn = $H[self::upper(self::HX_SIGNATURE)] ?? '';
            $digH = $H[self::upper(self::HX_BODY_DIGEST)] ?? '';

            if ($alg !== self::HMAC_ALG || $sigIn === '' || $digH === '') {
                throw new SecurePayloadException('Header HMAC tidak lengkap/salah algoritma', SecurePayloadException::BAD_REQUEST);
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

            if (!$hmacRaw) {
                throw new SecurePayloadException('Secret Key HMAC tidak ditemukan di server', SecurePayloadException::SERVER_ERROR);
            }

            // 2. Verifikasi Signature
            $msg = self::hmacMessage($this->version, $cid, $kid, $tsStr, $nonceB64, $method, $path, $qStr, $calcDig);
            $sigB64 = base64_encode(hash_hmac('sha256', $msg, (string) $hmacRaw, true));

            if (!hash_equals($sigB64, $sigIn)) {
                throw new SecurePayloadException('Tanda Tangan (Signature) tidak valid', SecurePayloadException::UNAUTHORIZED);
            }

            $result['mode'] = ($this->mode === 'both' and isset($rawBodyForHmac)) ? 'BOTH' : 'HMAC';
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

    // --- Private & Internal Helpers ---

    private function checkReplay(string $cid, string $kid, string $tsStr, string $nonceB64): void
    {
        $cacheKey = 'sp_' . substr(hash('sha256', "$cid|$kid|$tsStr|$nonceB64"), 0, 48);

        if ($this->replayStore) {
            $okNew = (bool) call_user_func($this->replayStore, $cacheKey, $this->replayTtl);
            if (!$okNew) {
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
            $age = time() - (int) @filemtime($f);
            if ($age < $this->replayTtl) {
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

                // Jika baru saja disentuh oleh proses lain dalam durasi TTL
                if ($stat['size'] > 0 && $age < $this->replayTtl) {
                    flock($fp, LOCK_UN);
                    fclose($fp);
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

    private function getAeadKeyRaw(): string
    {
        $aeadKeyRaw = base64_decode($this->aeadKeyB64 ?? '', true);
        if (!is_string($aeadKeyRaw) || strlen($aeadKeyRaw) !== 32) {
            throw new SecurePayloadException('Kunci AEAD tidak valid (harus 32 byte base64)', SecurePayloadException::BAD_REQUEST);
        }
        return $aeadKeyRaw;
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

    private function aeadAAD(string $version): string
    {
        return 'v' . $version;
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
}
