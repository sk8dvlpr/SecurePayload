<?php

declare(strict_types=1);

namespace SecurePayload\Delivery;

use SecurePayload\Delivery\Internal\LinkCodec;
use SecurePayload\Exceptions\SecurePayloadException;

/**
 * Penerbit token tautan aman untuk delivery file.
 *
 * Token berformat compact `sp1.<b64url(payloadJSON)>.<b64url(sig)>` dengan
 * signature HMAC-SHA256 atas string kanonik (bukan atas byte JSON, sehingga
 * urutan key JSON tidak memengaruhi verifikasi). Modul ini STANDALONE: tidak
 * bergantung pada facade SecurePayload maupun protokol request/response.
 *
 * Payload token: {file_id:string, exp:int(unix), iat:int, jti:string(32 hex),
 * su:bool, bound_to:?string}. jti dihasilkan acak per token sehingga dua
 * pemanggilan issue() dengan parameter identik tetap menghasilkan token beda.
 *
 * Keamanan:
 * - Secret minimal 32 karakter (konsisten dengan konvensi library).
 * - fileId/boundTo wajib bebas whitespace/karakter kontrol karena masuk
 *   string kanonik berbasis "\n" (mencegah ambiguitas antar-kolom).
 * - Format file id TIDAK divalidasi di sini (milik layer Storage);
 *   cukup non-kosong dan aman-kanonik.
 */
final class SecureLinkIssuer
{
    /** TTL maksimum default (detik): 24 jam. */
    public const DEFAULT_TTL_MAX = 86400;

    /** Panjang minimum HMAC secret (byte), konsisten dengan SecurePayloadConfig. */
    private const MIN_SECRET_LENGTH = 32;

    private string $hmacSecret;
    private int $ttlMax;

    /** @var callable callable():int — sumber waktu unix (injectable demi test deterministik) */
    private $clock;

    /**
     * @param string $hmacSecret Secret HMAC bersama penerbit & verifikator (minimal 32 karakter).
     * @param array{clock?:callable, ttlMax?:int} $opts
     *        clock : callable():int sumber waktu (default time()).
     *        ttlMax: batas atas TTL token dalam detik (default 86400).
     *
     * @throws SecurePayloadException BAD_REQUEST bila secret terlalu pendek atau opts tidak valid.
     */
    public function __construct(string $hmacSecret, array $opts = [])
    {
        if (strlen($hmacSecret) < self::MIN_SECRET_LENGTH) {
            throw new SecurePayloadException(
                'HMAC Secret terlalu pendek. Minimum 32 karakter (rekomendasikan 64 byte hex).',
                SecurePayloadException::BAD_REQUEST
            );
        }
        $ttlMax = $opts['ttlMax'] ?? self::DEFAULT_TTL_MAX;
        if (!is_int($ttlMax) || $ttlMax <= 0) {
            throw new SecurePayloadException('ttlMax wajib bertipe integer positif', SecurePayloadException::BAD_REQUEST);
        }
        if (isset($opts['clock']) && !is_callable($opts['clock'])) {
            throw new SecurePayloadException('clock wajib berupa callable', SecurePayloadException::BAD_REQUEST);
        }
        $this->hmacSecret = $hmacSecret;
        $this->ttlMax = $ttlMax;
        $this->clock = $opts['clock'] ?? static fn (): int => time();
    }

    /**
     * Terbitkan token tautan untuk satu file.
     *
     * @param string   $fileId    ID file milik layer Storage (non-kosong, bebas whitespace/kontrol).
     * @param int      $ttl       Umur token dalam detik; wajib 1..ttlMax.
     * @param bool     $singleUse True bila token hanya boleh diverifikasi sekali (butuh replayStore di Verifier).
     * @param ?string  $boundTo   Identitas pemegang yang diikat (mis. client id); null = tidak terikat.
     *
     * @return string Token `sp1.<payload>.<sig>` — URL-safe (alfabet base64url, tanpa padding).
     *
     * @throws SecurePayloadException BAD_REQUEST bila ttl <= 0 / > ttlMax,
     *                                fileId kosong/mengandung whitespace atau karakter kontrol,
     *                                boundTo non-null dengan syarat sama.
     */
    public function issue(string $fileId, int $ttl, bool $singleUse = true, ?string $boundTo = null): string
    {
        self::assertSafeText($fileId, 'fileId');
        if ($boundTo !== null) {
            self::assertSafeText($boundTo, 'boundTo');
        }
        if ($ttl <= 0 || $ttl > $this->ttlMax) {
            throw new SecurePayloadException(
                "ttl harus di rentang 1..{$this->ttlMax} detik",
                SecurePayloadException::BAD_REQUEST
            );
        }

        $iat = ($this->clock)();
        $claims = [
            'file_id' => $fileId,
            'exp' => $iat + $ttl,
            'iat' => $iat,
            'jti' => bin2hex(random_bytes(16)),
            'su' => $singleUse,
            'bound_to' => $boundTo,
        ];

        $json = json_encode($claims, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            throw new SecurePayloadException('Gagal mengencode payload token', SecurePayloadException::SERVER_ERROR);
        }

        return LinkCodec::buildToken($json, LinkCodec::sign(LinkCodec::canonicalString($claims), $this->hmacSecret));
    }

    /**
     * Validasi teks yang akan masuk string kanonik berbasis "\n":
     * non-kosong dan bebas whitespace/karakter kontrol (fail-closed).
     *
     * @throws SecurePayloadException BAD_REQUEST bila tidak aman.
     */
    private static function assertSafeText(string $value, string $field): void
    {
        if ($value === '') {
            throw new SecurePayloadException("$field wajib non-kosong", SecurePayloadException::BAD_REQUEST);
        }
        if (preg_match('/[\s\x00-\x1F\x7F]/', $value) === 1) {
            throw new SecurePayloadException(
                "$field tidak boleh mengandung whitespace/newline/karakter kontrol",
                SecurePayloadException::BAD_REQUEST
            );
        }
    }
}
