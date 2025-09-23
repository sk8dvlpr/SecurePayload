<?php
declare(strict_types=1);

namespace SecurePayload;

use SecurePayload\Exceptions\SecurePayloadException;

/**
 * SecurePayload
 * -------------
 * Satu kelas yang menggabungkan fungsi CLIENT dan SERVER untuk mengamankan request/response.
 * - Client: membangun header/signature dan body terenkripsi/tertanda (HMAC/AEAD/BOTH).
 * - Server: memverifikasi signature/digest, mencegah replay, dan mendekripsi payload.
 *
 * Fitur utama:
 * - Mode keamanan: 'hmac' | 'aead' | 'both'
 * - Nonce + anti-replay TTL
 * - Timestamp validation & clock skew tolerance
 * - Key source fleksibel: loader callable (ENV/DB/KMS)
 * - Error-handling eksplisit (array) atau exception melalui verifyOrThrow()
 */
final class SecurePayload
{

    public const HX_CLIENT_ID   = 'X-Client-Id';
    public const HX_KEY_ID      = 'X-Key-Id';
    public const HX_TIMESTAMP   = 'X-Timestamp';
    public const HX_NONCE       = 'X-Nonce';
    public const HX_SIG_VER     = 'X-Signature-Version';
    public const HX_SIG_ALG     = 'X-Signature-Algorithm';
    public const HX_SIGNATURE   = 'X-Signature';
    public const HX_BODY_DIGEST = 'X-Body-Digest';
    public const HX_CANON_REQ   = 'X-Canonical-Request';
    public const HX_AEAD_NONCE  = 'X-AEAD-Nonce';
    public const HX_AEAD_ALG    = 'X-AEAD-Algorithm';

    public const HMAC_ALG = 'HMAC-SHA256';
    public const AEAD_ALG = 'XCHACHA20-POLY1305-IETF';
    public const DEFAULT_VERSION = '1';

    /** @var 'hmac'|'aead'|'both' */
    private string $mode;
    private string $version;

    private ?string $clientId;
    private ?string $keyId;
    private ?string $hmacSecretRaw;
    private ?string $aeadKeyB64;

    /** @var callable|null function(string,string): array{hmacSecret:?string,aeadKeyB64:?string} */
    private $keyLoader;

    /** @var callable|null function(string,int): bool */
    private $replayStore;

    private int $replayTtl = 120;
    private int $clockSkew = 60;

    /**
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
     * } $opts Konfigurasi awal.
     * @throws SecurePayloadException
     */
    public function __construct(array $opts = [])
    {
        $this->mode         = $opts['mode']      ?? 'both';
        $this->version      = $opts['version']   ?? self::DEFAULT_VERSION;
        $this->clientId     = $opts['clientId']  ?? null;
        $this->keyId        = $opts['keyId']     ?? null;
        $this->hmacSecretRaw= $opts['hmacSecretRaw'] ?? null;
        $this->aeadKeyB64   = $opts['aeadKeyB64']    ?? null;
        $this->keyLoader    = $opts['keyLoader'] ?? null;
        $this->replayStore  = $opts['replayStore'] ?? null;
        $this->replayTtl    = isset($opts['replayTtl']) ? (int)$opts['replayTtl'] : 120;
        $this->clockSkew    = isset($opts['clockSkew']) ? (int)$opts['clockSkew'] : 60;

        if (!in_array($this->mode, ['hmac','aead','both'], true)) {
            throw new SecurePayloadException('Invalid mode: '.$this->mode, SecurePayloadException::BAD_REQUEST);
        }
        if ($this->version === '') {
            throw new SecurePayloadException('Version cannot be empty', SecurePayloadException::BAD_REQUEST);
        }
    }

    /** @return array{0: array<string,string>, 1: string} */
    /**
     * Client-side: membangun header keamanan + body yang sesuai mode.
     *
     * - HMAC: Body = JSON plaintext, header berisi digest & signature.
     * - AEAD: Body = JSON {"__aead_b64": base64(ciphertext)}, header berisi AEAD nonce.
     * - BOTH: Enkripsi plaintext + tanda tangan digest plaintext.
     *
     * @param string $url     URL lengkap (digunakan untuk canonical path & query)
     * @param string $method  HTTP method (GET/POST/PUT/DELETE...)
     * @param array  $payload Data yang akan dikirim (akan di-JSON-kan)
     * @return array{0: array<string,string>, 1: string} [headers, body]
     * @throws SecurePayloadException Ketika konfigurasi tidak valid / kunci tidak tersedia / JSON gagal.
     */
    public function buildHeadersAndBody(string $url, string $method, array $payload): array
    {
        if (!in_array($this->mode, ['hmac','aead','both'], true)) {
            throw new SecurePayloadException('Unsupported mode', SecurePayloadException::BAD_REQUEST);
        }
        if (($this->clientId ?? '') === '' || ($this->keyId ?? '') === '') {
            throw new SecurePayloadException('clientId & keyId are required for client mode', SecurePayloadException::BAD_REQUEST);
        }

        $method = strtoupper($method);
        $parts = parse_url($url);
        if ($parts === false) {
            throw new SecurePayloadException('Invalid URL', SecurePayloadException::BAD_REQUEST);
        }
        $path  = self::normalizePath($parts['path'] ?? '/');
        $qStr  = '';
        if (!empty($parts['query'])) {
            parse_str($parts['query'], $qArr);
            if (!is_array($qArr)) $qArr = [];
            $qStr = self::canonicalQuery($qArr);
        }

        $ver      = $this->version;
        $ts       = (string) time();
        $nonceB64 = self::genNonceB64();

        $headers = [
            self::HX_CLIENT_ID => (string)$this->clientId,
            self::HX_KEY_ID    => (string)$this->keyId,
            self::HX_TIMESTAMP => $ts,
            self::HX_NONCE     => $nonceB64,
            self::HX_SIG_VER   => $ver,
            self::HX_CANON_REQ => $method . "\n" . $path . "\n" . $qStr,
        ];

        if ($this->mode === 'aead') {
            $body = json_encode($payload, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
            if ($body === false) throw new SecurePayloadException('JSON encode failed', SecurePayloadException::BAD_REQUEST);
            if (!extension_loaded('sodium')) {
                throw new SecurePayloadException('ext-sodium required for AEAD mode', SecurePayloadException::SERVER_ERROR);
            }
            $aeadKeyB64 = $this->aeadKeyB64;
            $aeadKeyRaw = base64_decode($aeadKeyB64 ?? '', true);
            if (!is_string($aeadKeyRaw) || strlen($aeadKeyRaw) !== 32) {
                throw new SecurePayloadException('Invalid AEAD key (base64 of 32 bytes required)', SecurePayloadException::BAD_REQUEST);
            }

            $aeadNonce  = self::aeadNonceFrom($nonceB64, $method, $path, $qStr);
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($body, $this->aeadAAD($ver), $aeadNonce, $aeadKeyRaw);
$bodyB64    = base64_encode($ciphertext);

            $headers[self::HX_AEAD_ALG]   = self::AEAD_ALG;
            $headers[self::HX_AEAD_NONCE] = base64_encode($aeadNonce);

            return [$headers, json_encode(['__aead_b64' => $bodyB64], JSON_UNESCAPED_SLASHES)];
        }

        if ($this->mode === 'both') {
            $plain = json_encode($payload, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
            if ($plain === false) throw new SecurePayloadException('JSON encode failed', SecurePayloadException::BAD_REQUEST);
            if (!extension_loaded('sodium')) {
                throw new SecurePayloadException('ext-sodium required for BOTH mode', SecurePayloadException::SERVER_ERROR);
            }
            $aeadKeyB64 = $this->aeadKeyB64;
            $aeadKeyRaw = base64_decode($aeadKeyB64 ?? '', true);
            if (!is_string($aeadKeyRaw) || strlen($aeadKeyRaw) !== 32) {
                throw new SecurePayloadException('Invalid AEAD key (base64 of 32 bytes required)', SecurePayloadException::BAD_REQUEST);
            }

            $aeadNonce  = self::aeadNonceFrom($nonceB64, $method, $path, $qStr);
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plain, $this->aeadAAD($ver), $aeadNonce, $aeadKeyRaw);
$ctB64      = base64_encode($ciphertext);
            $body       = json_encode(['__aead_b64' => $ctB64], JSON_UNESCAPED_SLASHES);

            $digestB64 = self::bodyDigestB64($plain);
            $msg       = self::hmacMessage($ver, (string)$this->clientId, (string)$this->keyId, $ts, $nonceB64, $method, $path, $qStr, $digestB64);
            $hmac = hash_hmac('sha256', $msg, (string)$this->hmacSecretRaw, true);
            $sigB64    = base64_encode($hmac);

            $headers[self::HX_AEAD_ALG]    = self::AEAD_ALG;
            $headers[self::HX_AEAD_NONCE]  = base64_encode($aeadNonce);
            $headers[self::HX_SIG_ALG]     = self::HMAC_ALG;
            $headers[self::HX_BODY_DIGEST] = 'sha256=' . $digestB64;
            $headers[self::HX_SIGNATURE]   = $sigB64;

            return [$headers, $body];
        }

        // HMAC only
        $plain     = json_encode($payload, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
        if ($plain === false) throw new SecurePayloadException('JSON encode failed', SecurePayloadException::BAD_REQUEST);
        $digestB64 = self::bodyDigestB64($plain);
        $msg       = self::hmacMessage($ver, (string)$this->clientId, (string)$this->keyId, $ts, $nonceB64, $method, $path, $qStr, $digestB64);
        $hmac = hash_hmac('sha256', $msg, (string)$this->hmacSecretRaw, true);
        $sigB64    = base64_encode($hmac);

        $headers[self::HX_SIG_ALG]     = self::HMAC_ALG;
        $headers[self::HX_BODY_DIGEST] = 'sha256=' . $digestB64;
        $headers[self::HX_SIGNATURE]   = $sigB64;

        return [$headers, $plain];
    }

    /** @return array{status:int, headers:array<string,string>, body:mixed, error:?string} */
    /**
     * Helper opsional untuk mengirim request via cURL.
     * Memanggil buildHeadersAndBody() lalu melakukan HTTP request.
     *
     * @param string               $url           URL tujuan
     * @param string               $method        HTTP method
     * @param array                $payload       Data payload
     * @param array<string,string> $extraHeaders  Header tambahan (akan digabung)
     * @return array{status:int, headers:array<string,string>, body:mixed, error:?string}
     * @throws SecurePayloadException Jika ext-curl tidak ada atau buildHeadersAndBody gagal.
     */
    public function send(string $url, string $method, array $payload, array $extraHeaders = []): array
    {
        if (!function_exists('curl_init')) {
            throw new SecurePayloadException('ext-curl is required for send()', SecurePayloadException::SERVER_ERROR);
        }
        [$headers, $body] = $this->buildHeadersAndBody($url, $method, $payload);

        $outHeaders = [];
        foreach ($headers + $extraHeaders as $k => $v) {
            $outHeaders[] = $k . ': ' . $v;
        }

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array_merge($outHeaders, ['Content-Type: application/json']));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);

        $resp = curl_exec($ch);
        $err  = $resp === false ? curl_error($ch) : null;
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $rawHeaders = substr((string)$resp, 0, $headerSize);
        $bodyStr    = substr((string)$resp, $headerSize);
        curl_close($ch);

        $respHeaders = [];
        foreach (preg_split("/\r?\n/", $rawHeaders) as $line) {
            if (strpos($line, ':') !== false) {
                [$hk, $hv] = array_map('trim', explode(':', $line, 2));
                if ($hk !== '') $respHeaders[$hk] = $hv;
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

    /** @return array{ok:bool, status?:int, error?:string, debug?:array<string,mixed>, mode?:string, bodyPlain?:string, json?:mixed} */
    /**
     * Server-side: verifikasi request.
     * Mengembalikan array aman untuk dikonsumsi handler (tanpa exception).
     *
     * @param array<string,string>    $headers Header HTTP request
     * @param string                  $rawBody Body mentah (string)
     * @param string                  $method  HTTP method
     * @param string                  $path    Path ("/api/..."), tanpa domain
     * @param array|string             $query   Array query (key=>val) atau string query
     * @return array{ok:bool, status?:int, error?:string, debug?:array<string,mixed>, mode?:string, bodyPlain?:string, json?:mixed}
     */
    public function verify(array $headers, string $rawBody, string $method, string $path, $query): array
    {
        try {
            $data = $this->verifyOrThrow($headers, $rawBody, $method, $path, $query);
            return ['ok'=>true] + $data;
        } catch (SecurePayloadException $e) {
            return [
                'ok' => false,
                'status' => $e->getCode() ?: SecurePayloadException::BAD_REQUEST,
                'error' => $e->getMessage(),
                'debug' => $e->getContext(),
                'mode' => "",
                'bodyPlain' => "",
                'json'  => null,
            ];
        }
    }

    /** @return array{mode:string, bodyPlain:string|null, json:mixed} */
    /**
     * Server-side: verifikasi request dan lempar exception bila invalid.
     *
     * @param array<string,string> $headers
     * @param string               $rawBody
     * @param string               $method
     * @param string               $path
     * @param array|string         $query
     * @return array{mode:string, bodyPlain:string|null, json:mixed}
     * @throws SecurePayloadException Untuk semua kondisi tidak valid (header kurang, timestamp, replay, AEAD/HMAC gagal, dll.).
     */
    public function verifyOrThrow(array $headers, string $rawBody, string $method, string $path, $query): array
    {
        $H = [];
        foreach ($headers as $k => $v) {
            if (!is_string($k)) continue;
            $H[strtoupper($k)] = (string)$v;
        }

        $ver   = $H[self::upper(self::HX_SIG_VER)] ?? '';
        $cid   = $H[self::upper(self::HX_CLIENT_ID)] ?? '';
        $kid   = $H[self::upper(self::HX_KEY_ID)] ?? '';
        $tsStr = $H[self::upper(self::HX_TIMESTAMP)] ?? '';
        $nonceB64 = $H[self::upper(self::HX_NONCE)] ?? '';

        if ($ver === '' || $cid === '' || $kid === '' || $tsStr === '' || $nonceB64 === '') {
            throw new SecurePayloadException('Missing required headers', SecurePayloadException::BAD_REQUEST);
        }
        if ($ver !== $this->version) {
            throw new SecurePayloadException('Unsupported version', SecurePayloadException::BAD_REQUEST, ['got'=>$ver,'expected'=>$this->version]);
        }
        if (!preg_match('/^\d+$/', $tsStr)) {
            throw new SecurePayloadException('Bad timestamp', SecurePayloadException::BAD_REQUEST, ['value'=>$tsStr]);
        }

        $ts = (int)$tsStr; $now = time();
        if ($ts > $now + $this->clockSkew || $ts < $now - ($this->replayTtl + $this->clockSkew)) {
            throw new SecurePayloadException('Timestamp out of range', SecurePayloadException::UNAUTHORIZED, ['ts'=>$ts,'now'=>$now]);
        }

        $cacheKey = 'sp_' . substr(hash('sha256', $cid.'|'.$kid.'|'.$tsStr.'|'.$nonceB64), 0, 48);
        if ($this->replayStore) {
            $okNew = (bool) call_user_func($this->replayStore, $cacheKey, $this->replayTtl);
            if (!$okNew) throw new SecurePayloadException('Replay detected', SecurePayloadException::UNAUTHORIZED);
        } else {
            $f = sys_get_temp_dir().'/'.$cacheKey;
            if (file_exists($f)) {
                $age = time() - (int) @filemtime($f);
                if ($age < $this->replayTtl) {
                    throw new SecurePayloadException('Replay detected', SecurePayloadException::UNAUTHORIZED, ['age'=>$age]);
                }
            }
            @touch($f);
        }

        $method = strtoupper($method);
        $path   = self::normalizePath($path ?: '/');
        if (is_array($query)) $qStr = self::canonicalQuery($query);
        else { parse_str((string)$query, $qArr); $qStr = self::canonicalQuery(is_array($qArr)?$qArr:[]); }

        $hmacRaw = null; $aeadB64 = null;
        if ($this->keyLoader) {
            $keys = (array) call_user_func($this->keyLoader, $cid, $kid);
            $hmacRaw = $keys['hmacSecret'] ?? null;
            $aeadB64 = $keys['aeadKeyB64'] ?? null;
        }

        $used = null;
        $result = ['mode'=>null,'bodyPlain'=>null,'json'=>null];

        $aeadAlg = $H[self::upper(self::HX_AEAD_ALG)] ?? '';
        $aeadNonceHdrB64 = $H[self::upper(self::HX_AEAD_NONCE)] ?? '';
        if (($this->mode === 'aead' || $this->mode === 'both') && $aeadAlg === self::AEAD_ALG) {
            $json = json_decode($rawBody, true);
            $blobB64 = is_array($json) ? ($json['__aead_b64'] ?? '') : '';
            if ($blobB64 === '') throw new SecurePayloadException('Missing AEAD blob', SecurePayloadException::BAD_REQUEST);

            if (!extension_loaded('sodium')) throw new SecurePayloadException('ext-sodium required', SecurePayloadException::SERVER_ERROR);
            $keyRaw = base64_decode($aeadB64 ?? '', true);
            if (!is_string($keyRaw) || strlen($keyRaw) !== 32) throw new SecurePayloadException('AEAD key unavailable', SecurePayloadException::SERVER_ERROR);

            $nonceCalc = self::aeadNonceFrom($nonceB64, $method, $path, $qStr);
            $nonceHdr  = base64_decode($aeadNonceHdrB64, true) ?: '';
            if (!hash_equals($nonceHdr, $nonceCalc)) {
                throw new SecurePayloadException('AEAD nonce mismatch', SecurePayloadException::UNAUTHORIZED);
            }

            $ct = base64_decode($blobB64, true);
            if ($ct === false) throw new SecurePayloadException('AEAD body corrupt (base64)', SecurePayloadException::BAD_REQUEST);

            $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ct, $this->aeadAAD($ver), $nonceCalc, $keyRaw);
            if ($plain === false) throw new SecurePayloadException('AEAD decrypt failed', SecurePayloadException::UNAUTHORIZED);

            $used = ($this->mode === 'both') ? 'BOTH-AEAD' : 'AEAD';
            $result['mode'] = $used;

            if ($this->mode === 'aead') {
                $result['bodyPlain'] = $plain;
                $result['json'] = json_decode($plain, true);
                return $result;
            }

            $rawBodyForHmac = $plain;
            $digestHdr = $H[self::upper(self::HX_BODY_DIGEST)] ?? '';
            $calc = 'sha256=' . self::bodyDigestB64($rawBodyForHmac);
            if ($digestHdr !== $calc) {
                throw new SecurePayloadException('Body digest mismatch', SecurePayloadException::UNPROCESSABLE, ['expected'=>$calc,'got'=>$digestHdr]);
            }
        }

        if ($this->mode === 'hmac' || $this->mode === 'both') {
            $alg   = $H[self::upper(self::HX_SIG_ALG)]     ?? '';
            $sigIn = $H[self::upper(self::HX_SIGNATURE)]   ?? '';
            $digH  = $H[self::upper(self::HX_BODY_DIGEST)] ?? '';
            if ($alg !== self::HMAC_ALG || $sigIn === '' || $digH === '') {
                throw new SecurePayloadException('Bad HMAC headers', SecurePayloadException::BAD_REQUEST);
            }
            $digHVal = str_starts_with($digH,'sha256=') ? substr($digH,7) : '';
            if ($digHVal === '') throw new SecurePayloadException('Bad digest format (sha256=...)', SecurePayloadException::BAD_REQUEST);

            $bodyForHmac = isset($rawBodyForHmac) ? $rawBodyForHmac : $rawBody;
            $calcDig = self::bodyDigestB64($bodyForHmac);
            if (!hash_equals($digHVal, $calcDig)) {
                throw new SecurePayloadException('Body digest mismatch', SecurePayloadException::UNPROCESSABLE);
            }
            if (!$hmacRaw) throw new SecurePayloadException('HMAC secret missing', SecurePayloadException::SERVER_ERROR);

            $msg    = self::hmacMessage($this->version, $cid, $kid, $tsStr, $nonceB64, $method, $path, $qStr, $calcDig);
            $sigB64 = base64_encode(hash_hmac('sha256', $msg, (string)$hmacRaw, true));

            if (!hash_equals($sigB64, $sigIn)) {
                throw new SecurePayloadException('Signature mismatch', SecurePayloadException::UNAUTHORIZED);
            }

            $result['mode'] = ($this->mode === 'both' and isset($rawBodyForHmac)) ? 'BOTH' : 'HMAC';
            $result['bodyPlain'] = $bodyForHmac;
            $result['json'] = json_decode($bodyForHmac, true);
            return $result;
        }

        throw new SecurePayloadException('No valid security headers', SecurePayloadException::BAD_REQUEST);
    }

    /**
     * Server-side (simple): cukup berikan headers + rawBody.
     * Method/Path/Query diambil dari header X-Canonical-Request (dibuat client).
     * @param array<string,string> $headers
     * @param string $rawBody
     * @return array{ok:bool, status?:int, error?:string, debug?:array<string,mixed>, mode?:string, bodyPlain?:string, json:mixed}
     */
    public function verifySimple(array $headers, string $rawBody): array
    {
        try {
            $data = $this->verifySimpleOrThrow($headers, $rawBody);
            return ['ok'=>true] + $data;
        } catch (\SecurePayload\Exceptions\SecurePayloadException $e) {
            return [
                'ok' => false,
                'status' => $e->getCode() ?: \SecurePayload\Exceptions\SecurePayloadException::BAD_REQUEST,
                'error' => $e->getMessage(),
                'debug' => $e->getContext(),
                'mode' => "",
                'bodyPlain' => "",
                'json'  => null,
            ];
        }
    }

    /**
     * Server-side (simple): lempar exception jika invalid.
     * Method/Path/Query dibaca dari header X-Canonical-Request.
     * @param array<string,string> $headers
     * @param string $rawBody
     * @return array{mode:string, bodyPlain:string|null, json:mixed}
     * @throws \SecurePayload\Exceptions\SecurePayloadException
     */
    public function verifySimpleOrThrow(array $headers, string $rawBody): array
    {
        // Normalisasi header jadi UPPER-KEY => value
        $H = [];
        foreach ($headers as $k => $v) {
            if (!is_string($k)) { continue; }
            $H[strtoupper($k)] = (string)$v;
        }

        $canon = $H[self::upper(self::HX_CANON_REQ)] ?? '';
        if ($canon === '') {
            throw new \SecurePayload\Exceptions\SecurePayloadException(
                'Missing ' . self::HX_CANON_REQ . ' header; gunakan verify() lama dengan method/path/query atau aktifkan header kanonik di client.',
                \SecurePayload\Exceptions\SecurePayloadException::BAD_REQUEST
            );
        }

        $parts = explode("\n", $canon, 3);
        if (count($parts) !== 3) {
            throw new \SecurePayload\Exceptions\SecurePayloadException(
                'Bad canonical request header format',
                \SecurePayload\Exceptions\SecurePayloadException::BAD_REQUEST
            );
        }
        [$method, $path, $qStr] = $parts;

        // Teruskan ke jalur verifikasi penuh yang sudah ada
        return $this->verifyOrThrow($headers, $rawBody, strtoupper($method), self::normalizePath($path), $qStr);
    }

    private static function upper(string $s): string { return strtoupper($s); }
    /** Normalisasi path URL: selalu diawali '/', dan tidak berakhiran '/' (kecuali root '/'). */
    public static function normalizePath(string $path): string
    {
        if ($path === '') return '/';
        if ($path[0] !== '/') $path = '/'.$path;
        if (strlen($path) > 1) $path = rtrim($path, '/');
        return $path;
    }
    /**
     * Canonicalisasi query (key sort ASC + urlencode) -> string 'a=1&b=2'.
     * @param array<string,mixed> $q
     */
    public static function canonicalQuery(array $q): string
    {
        if (!$q) return '';
        $out = [];
        ksort($q, SORT_STRING);
        foreach ($q as $k => $v) {
            if (is_array($v)) $v = implode(',', array_map('strval', $v));
            else $v = (string) $v;
            $out[] = rawurlencode((string)$k).'='.rawurlencode($v);
        }
        return implode('&', $out);
    }
    /** Generate nonce acak (16 byte) lalu encode base64. */
    public static function genNonceB64(): string { return base64_encode(random_bytes(16)); }
    /** Hitung SHA-256 digest dari body string dan kembalikan base64-nya. */
    public static function bodyDigestB64(string $body): string { return base64_encode(hash('sha256', $body, true)); }
    private function aeadAAD(string $version): string { return 'v'.$version; }
    /**
     * Turunkan AEAD nonce dari kombinasi (method, path, query, seedNonce) agar terikat ke request.
     * @return string Raw nonce 24 byte
     */
    public static function aeadNonceFrom(string $nonceB64, string $method, string $path, string $qStr): string
    {
        $seed = base64_decode($nonceB64, true) ?: random_bytes(16);
        $msg = implode("\n", [strtoupper($method), self::normalizePath($path), (string)$qStr, $seed]);
        $h = hash('sha256', $msg, true);
        $len = defined('SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES') ? (int)SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES : 24;
        return substr($h, 0, $len);
    }
    /**
     * Buat canonical message untuk HMAC agar stabil & mudah diverifikasi.
     * Lihat README untuk format detail tiap baris.
     */
    public static function hmacMessage(string $ver, string $clientId, string $keyId, string $ts, string $nonceB64, string $method, string $path, string $qStr, string $bodyDigestB64): string
    {
        return implode("\n", [
            'v'.$ver,
            'client='.$clientId,
            'key='.$keyId,
            'ts='.$ts,
            'nonce='.$nonceB64,
            'm='.$method,
            'p='.$path,
            'q='.$qStr,
            'bd=sha256:'.$bodyDigestB64,
            '',
        ]);
    }
}
