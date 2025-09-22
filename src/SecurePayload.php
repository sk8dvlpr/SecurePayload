<?php
declare(strict_types=1);

namespace SecurePayload;

use RuntimeException;

/**
 * Unified client+server helper for HMAC + AEAD (XChaCha20-Poly1305-IETF).
 * - Native PHP (tanpa CI4), PSR-4.
 * - Menyatukan fungsi dari SecurePayloadClient & SecurePayloadServer lama.
 */
final class SecurePayload
{
    /* ==== Header constants (case-sensitive saat kirim; server pakai strtoupper untuk lookup) ==== */
    public const HX_CLIENT_ID   = 'X-Client-Id';
    public const HX_KEY_ID      = 'X-Key-Id';
    public const HX_TIMESTAMP   = 'X-Timestamp';
    public const HX_NONCE       = 'X-Nonce';
    public const HX_SIG_VER     = 'X-Signature-Version';
    public const HX_SIG_ALG     = 'X-Signature-Algorithm';
    public const HX_SIGNATURE   = 'X-Signature';
    public const HX_BODY_DIGEST = 'X-Body-Digest';
    public const HX_AEAD_NONCE  = 'X-AEAD-Nonce';
    public const HX_AEAD_ALG    = 'X-AEAD-Algorithm';

    /* ==== Algorithms / Versions ==== */
    public const HMAC_ALG = 'HMAC-SHA256';
    public const AEAD_ALG = 'XCHACHA20-POLY1305-IETF'; // libsodium
    public const DEFAULT_VERSION = '1';

    /** @var 'hmac'|'aead'|'both' */
    private string $mode;
    private string $version;

    // --- Client creds (optional; diperlukan saat build header/ send) ---
    private ?string $clientId;
    private ?string $keyId;
    private ?string $hmacSecretRaw;
    private ?string $aeadKeyB64;

    /** @var callable|null function(string $clientId, string $keyId): array{hmacSecret:?string,aeadKeyB64:?string} */
    private $keyLoader;

    /** @var callable|null function(string $cacheKey, int $ttlSec): bool   (shouldReturnTrueIfNew) */
    private $replayStore;

    /** Anti-replay default TTL (detik) */
    private int $replayTtl = 120;

    /** Toleransi clock skew (detik) */
    private int $clockSkew = 60;

    /**
     * @param array{
     *   mode?: 'hmac'|'aead'|'both',
     *   version?: string,
     *   clientId?: ?string,
     *   keyId?: ?string,
     *   hmacSecretRaw?: ?string,
     *   aeadKeyB64?: ?string,
     *   keyLoader?: callable(string,string):array,
     *   replayStore?: callable(string,int):bool,
     *   replayTtl?: int,
     *   clockSkew?: int
     * } $opts
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
    }

    /* =====================================================
       =============== CLIENT  (build & send) ===============
       ===================================================== */

    /**
     * Build security headers + body (json) sesuai mode.
     * @return array{0:array<string,string>,1:string} [headers, body]
     */
    public function buildHeadersAndBody(string $url, string $method, array $payload): array
    {
        $method = strtoupper($method);
        $parts = parse_url($url);
        $path  = self::normalizePath($parts['path'] ?? '/');
        $qStr  = '';
        if (!empty($parts['query'])) {
            parse_str($parts['query'], $qArr);
            $qStr = self::canonicalQuery(is_array($qArr) ? $qArr : []);
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
        ];

        if ($this->mode === 'aead') {
            $body = json_encode($payload, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
            if (!extension_loaded('sodium')) {
                throw new RuntimeException('ext-sodium required for AEAD mode');
            }
            $aeadKeyRaw = base64_decode((string)$this->aeadKeyB64, true);
            if ($aeadKeyRaw === false || strlen($aeadKeyRaw) !== 32) {
                throw new RuntimeException('Invalid AEAD key (need base64 of 32 bytes)');
            }

            $aeadNonce  = self::aeadNonceFrom($nonceB64, $method, $path, $qStr);
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($body, $this->aeadAAD($ver), $aeadNonce, $aeadKeyRaw);
            $bodyB64    = base64_encode($ciphertext);

            $headers[self::HX_AEAD_ALG]   = self::AEAD_ALG;
            $headers[self::HX_AEAD_NONCE] = base64_encode($aeadNonce);

            return [$headers, json_encode(['__aead_b64' => $bodyB64], JSON_UNESCAPED_SLASHES)];
        }

        if ($this->mode === 'both') {
            // Encrypt first (AEAD), then still sign HMAC over digest of plaintext
            $plain = json_encode($payload, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
            if (!extension_loaded('sodium')) {
                throw new RuntimeException('ext-sodium required for BOTH mode');
            }
            $aeadKeyRaw = base64_decode((string)$this->aeadKeyB64, true);
            if ($aeadKeyRaw === false || strlen($aeadKeyRaw) !== 32) {
                throw new RuntimeException('Invalid AEAD key (need base64 of 32 bytes)');
            }

            $aeadNonce  = self::aeadNonceFrom($nonceB64, $method, $path, $qStr);
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plain, $this->aeadAAD($ver), $aeadNonce, $aeadKeyRaw);
            $ctB64      = base64_encode($ciphertext);
            $body       = json_encode(['__aead_b64' => $ctB64], JSON_UNESCAPED_SLASHES);

            // HMAC over plaintext digest
            $digestB64 = self::bodyDigestB64($plain);
            $msg       = self::hmacMessage($ver, (string)$this->clientId, (string)$this->keyId, $ts, $nonceB64, $method, $path, $qStr, $digestB64);
            $sigB64    = base64_encode(hash_hmac('sha256', $msg, (string)$this->hmacSecretRaw, true));

            $headers[self::HX_AEAD_ALG]   = self::AEAD_ALG;
            $headers[self::HX_AEAD_NONCE] = base64_encode($aeadNonce);
            $headers[self::HX_SIG_ALG]     = self::HMAC_ALG;
            $headers[self::HX_BODY_DIGEST] = 'sha256=' . $digestB64;
            $headers[self::HX_SIGNATURE]   = $sigB64;

            return [$headers, $body];
        }

        // HMAC only
        $plain     = json_encode($payload, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
        $digestB64 = self::bodyDigestB64($plain);
        $msg       = self::hmacMessage($ver, (string)$this->clientId, (string)$this->keyId, $ts, $nonceB64, $method, $path, $qStr, $digestB64);
        $sigB64    = base64_encode(hash_hmac('sha256', $msg, (string)$this->hmacSecretRaw, true));

        $headers[self::HX_SIG_ALG]     = self::HMAC_ALG;
        $headers[self::HX_BODY_DIGEST] = 'sha256=' . $digestB64;
        $headers[self::HX_SIGNATURE]   = $sigB64;

        return [$headers, $plain];
    }

    /**
     * Helper kirim request via cURL (RAW body, tanpa chunked).
     * @return array{status:int, headers:array<string,string>, body:mixed, error:?string, sent_header_str:string}
     */
    public function send(string $url, string $method, array $payload, array $extraHeaders = []): array
    {
        [$headers, $body] = $this->buildHeadersAndBody($url, $method, $payload);

        // Header string
        $outHeaders = [];
        foreach ($headers + $extraHeaders as $k => $v) {
            $outHeaders[] = $k . ': ' . $v;
        }
        $outHeadersStr = implode("\r\n", $outHeaders);

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
                $respHeaders[$hk] = $hv;
            }
        }
        $json = json_decode($bodyStr, true);
        return [
            'status' => $code,
            'headers' => $respHeaders,
            'body' => $json !== null ? $json : $bodyStr,
            'error' => $err,
            'sent_header_str' => $outHeadersStr,
        ];
    }

    /* =====================================================
       =============== SERVER (verify request) ==============
       ===================================================== */

    /**
     * @param array<string,string> $headers Headers request; boleh case-insensitive (akan dinormalisasi)
     * @param string $rawBody RAW body string dari http
     * @param string $method HTTP method
     * @param string $path URL path ("/api/foo")
     * @param array<string,mixed>|string $query Query array (akan dicannonical-kan) atau query string
     * @return array{
     *  ok:bool, status?:int, error?:string,
     *  mode?:string, bodyPlain?:string, json?:mixed,
     *  debug?:array<string,mixed>
     * }
     */
    public function verify(array $headers, string $rawBody, string $method, string $path, $query): array
    {
        $H = [];
        foreach ($headers as $k => $v) {
            $H[strtoupper($k)] = $v;
        }

        $ver   = $H[self::upper(self::HX_SIG_VER)] ?? '';
        $cid   = $H[self::upper(self::HX_CLIENT_ID)] ?? '';
        $kid   = $H[self::upper(self::HX_KEY_ID)] ?? '';
        $tsStr = $H[self::upper(self::HX_TIMESTAMP)] ?? '';
        $nonceB64 = $H[self::upper(self::HX_NONCE)] ?? '';

        if (!$ver || !$cid || !$kid || !$tsStr || !$nonceB64) {
            return ['ok'=>false,'status'=>400,'error'=>'Missing required headers'];
        }
        if ($ver !== $this->version) {
            return ['ok'=>false,'status'=>400,'error'=>'Unsupported version'];
        }

        // timestamp validation
        if (!preg_match('/^\d+$/', $tsStr)) return ['ok'=>false,'status'=>400,'error'=>'Bad timestamp'];
        $ts = (int)$tsStr;
        $now = time();
        if ($ts > $now + $this->clockSkew || $ts < $now - ($this->replayTtl + $this->clockSkew)) {
            return ['ok'=>false,'status'=>401,'error'=>'Timestamp out of range'];
        }

        // anti-replay
        $cacheKey = 'sp_' . substr(hash('sha256', $cid.'|'.$kid.'|'.$tsStr.'|'.$nonceB64), 0, 48);
        if ($this->replayStore) {
            $okNew = (bool) call_user_func($this->replayStore, $cacheKey, $this->replayTtl);
            if (!$okNew) return ['ok'=>false,'status'=>401,'error'=>'Replay detected'];
        } else {
            $f = sys_get_temp_dir().'/'.$cacheKey;
            if (file_exists($f)) return ['ok'=>false,'status'=>401,'error'=>'Replay detected'];
            @touch($f);
        }

        $method = strtoupper($method);
        $path   = self::normalizePath($path ?: '/');
        if (is_array($query)) {
            $qStr = self::canonicalQuery($query);
        } else {
            parse_str((string)$query, $qArr);
            $qStr = self::canonicalQuery(is_array($qArr)?$qArr:[]);
        }

        // resolve keys
        $hmacRaw = null;
        $aeadB64 = null;
        if ($this->keyLoader) {
            $keys = (array) call_user_func($this->keyLoader, $cid, $kid);
            $hmacRaw = $keys['hmacSecret'] ?? null;
            $aeadB64 = $keys['aeadKeyB64'] ?? null;
        }

        $used = null;
        $debug = [];

        // AEAD verify/decrypt
        $aeadAlg = $H[self::upper(self::HX_AEAD_ALG)] ?? '';
        $aeadNonceHdrB64 = $H[self::upper(self::HX_AEAD_NONCE)] ?? '';
        if (($this->mode === 'aead' || $this->mode === 'both') && $aeadAlg === self::AEAD_ALG) {
            $json = json_decode($rawBody, true);
            $blobB64 = is_array($json) ? ($json['__aead_b64'] ?? '') : '';
            if (!$blobB64) return ['ok'=>false,'status'=>400,'error'=>'Missing AEAD blob'];

            if (!extension_loaded('sodium')) return ['ok'=>false,'status'=>500,'error'=>'ext-sodium required'];
            $keyRaw = base64_decode((string)$aeadB64, true);
            if ($keyRaw === false || strlen($keyRaw) !== 32) return ['ok'=>false,'status'=>500,'error'=>'AEAD key unavailable'];

            $nonceCalc = self::aeadNonceFrom($nonceB64, $method, $path, $qStr);
            $nonceHdr  = base64_decode($aeadNonceHdrB64, true) ?: '';
            if (!hash_equals($nonceHdr, $nonceCalc)) {
                return ['ok'=>false,'status'=>401,'error'=>'AEAD nonce mismatch'];
            }

            $ct = base64_decode($blobB64, true);
            if ($ct === false) return ['ok'=>false,'status'=>400,'error'=>'AEAD body corrupt'];

            $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ct, $this->aeadAAD($ver), $nonceCalc, $keyRaw);
            if ($plain === false) return ['ok'=>false,'status'=>401,'error'=>'AEAD decrypt failed'];

            $used = ($this->mode === 'both') ? 'BOTH-AEAD' : 'AEAD';
            $debug['aead_nonce_b64'] = base64_encode($nonceCalc);

            if ($this->mode === 'aead') {
                return ['ok'=>true,'mode'=>$used,'bodyPlain'=>$plain,'json'=>json_decode($plain,true),'debug'=>$debug];
            }

            // if BOTH: keep $plain to validate HMAC too (over plaintext digest)
            $rawBodyForHmac = $plain;
            $digestHdr = $H[self::upper(self::HX_BODY_DIGEST)] ?? '';
            $calc = 'sha256=' . self::bodyDigestB64($rawBodyForHmac);
            if ($digestHdr !== $calc) return ['ok'=>false,'status'=>422,'error'=>'Body digest mismatch'];
        }

        // HMAC verify (works for HMAC-only or BOTH-HMAC path)
        if ($this->mode === 'hmac' || $this->mode === 'both') {
            $alg   = $H[self::upper(self::HX_SIG_ALG)]     ?? '';
            $sigIn = $H[self::upper(self::HX_SIGNATURE)]   ?? '';
            $digH  = $H[self::upper(self::HX_BODY_DIGEST)] ?? '';
            if ($alg !== self::HMAC_ALG || !$sigIn || !$digH) {
                return ['ok'=>false,'status'=>400,'error'=>'Bad HMAC headers'];
            }
            $digHVal = str_starts_with($digH,'sha256=') ? substr($digH,7) : '';
            if (!$digHVal) return ['ok'=>false,'status'=>400,'error'=>'Bad digest format'];

            $bodyForHmac = isset($rawBodyForHmac) ? $rawBodyForHmac : $rawBody; // BOTH uses plaintext
            $calcDig = self::bodyDigestB64($bodyForHmac);
            if (!hash_equals($digHVal, $calcDig)) {
                return ['ok'=>false,'status'=>422,'error'=>'Body digest mismatch'];
            }
            if (!$hmacRaw) return ['ok'=>false,'status'=>500,'error'=>'HMAC secret missing'];

            $msg    = self::hmacMessage($this->version, $cid, $kid, $tsStr, $nonceB64, $method, $path, $qStr, $calcDig);
            $sigB64 = base64_encode(hash_hmac('sha256', $msg, (string)$hmacRaw, true));

            if (!hash_equals($sigB64, $sigIn)) {
                return ['ok'=>false,'status'=>401,'error'=>'Signature mismatch'];
            }

            $debug['msg_b64'] = base64_encode($msg);
            $debug['sig_b64'] = $sigB64;
            $debug['body_digest_b64'] = $calcDig;

            $used = $used ? 'BOTH-HMAC' : 'HMAC';
            return ['ok'=>true,'mode'=>$used,'bodyPlain'=>$bodyForHmac,'json'=>json_decode($bodyForHmac,true),'debug'=>$debug];
        }

        return ['ok'=>false,'status'=>400,'error'=>'No valid security headers'];
    }

    /* ========================= Helpers ========================= */

    private static function upper(string $s): string { return strtoupper($s); }

    /** Normalisasi path: pastikan diawali '/', hilangkan trailing kecuali root */
    public static function normalizePath(string $path): string
    {
        if ($path === '') return '/';
        if ($path[0] !== '/') $path = '/'.$path;
        if (strlen($path) > 1) $path = rtrim($path, '/');
        return $path;
    }

    /** Canonical query: ksort by key, each value implode by ',', urlencode key/value (RFC3986-ish) */
    public static function canonicalQuery(array $q): string
    {
        if (!$q) return '';
        $out = [];
        ksort($q, SORT_STRING);
        foreach ($q as $k => $v) {
            if (is_array($v)) {
                $v = implode(',', array_map('strval', $v));
            } else {
                $v = (string) $v;
            }
            $out[] = rawurlencode((string)$k).'='.rawurlencode($v);
        }
        return implode('&', $out);
    }

    /** Nonce (base64) */
    public static function genNonceB64(): string
    {
        return base64_encode(random_bytes(16));
    }

    /** Digest base64 dari body (sha256 binary→b64) */
    public static function bodyDigestB64(string $body): string
    {
        return base64_encode(hash('sha256', $body, true));
    }

    /** AEAD AAD tergantung versi */
    private function aeadAAD(string $version): string
    {
        return 'v'.$version;
    }

    /** AEAD nonce diturunkan dari nonceB64+method+path+qStr (stabil 24 byte) */
    public static function aeadNonceFrom(string $nonceB64, string $method, string $path, string $qStr): string
    {
        $seed = base64_decode($nonceB64, true) ?: random_bytes(16);
        $msg = implode("\n", [strtoupper($method), self::normalizePath($path), (string)$qStr, $seed]);
        $h = hash('sha256', $msg, true);
        // 24 bytes untuk XChaCha20-Poly1305-IETF
        return substr($h, 0, 24);
    }

    /** Compose HMAC message (stable) */
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
