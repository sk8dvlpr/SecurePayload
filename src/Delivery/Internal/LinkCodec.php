<?php

declare(strict_types=1);

namespace SecurePayload\Delivery\Internal;

/**
 * Codec token SecureLink (internal modul Secure Delivery).
 *
 * Satu-satunya tempat yang mendefinisikan format wire token
 * `sp1.<b64url(payloadJSON)>.<b64url(sig)>` beserta aturan string kanonik
 * HMAC-SHA256-nya, agar Issuer dan Verifier tidak mungkin saling bergeser
 * (drift) pada logika kriptografis yang krusial ini.
 *
 * String kanonik: implode("\n", ['sp1', file_id, exp, jti, su, bound_to]).
 * Karena pemisahnya "\n", SEMUA komponen teks wajib bebas whitespace/karakter
 * kontrol (divalidasi di Issuer/Verifier sebelum masuk sini).
 */
final class LinkCodec
{
    /** Prefix versi format token. */
    public const VERSION = 'sp1';

    private function __construct()
    {
        // Kelas util statis murni — tidak untuk diinstansiasi.
    }

    /**
     * Bangun string kanonik untuk ditandatangani/diverifikasi.
     *
     * @param array{file_id:string, exp:int, jti:string, su:bool, bound_to:?string} $claims
     *        Klaim tervalidasi (tipe dijamin pemanggil).
     */
    public static function canonicalString(array $claims): string
    {
        return implode("\n", [
            self::VERSION,
            $claims['file_id'],
            (string) $claims['exp'],
            $claims['jti'],
            $claims['su'] ? '1' : '0',
            $claims['bound_to'] ?? '',
        ]);
    }

    /**
     * Hitung signature HMAC-SHA256 (binary raw) atas string kanonik.
     */
    public static function sign(string $canonical, string $hmacSecret): string
    {
        return hash_hmac('sha256', $canonical, $hmacSecret, true);
    }

    /**
     * Susun token lengkap dari payload JSON + signature binary.
     */
    public static function buildToken(string $payloadJson, string $sigRaw): string
    {
        return self::VERSION . '.' . self::encodeB64Url($payloadJson) . '.' . self::encodeB64Url($sigRaw);
    }

    /**
     * Encode biner/teks ke base64url tanpa padding (URL-safe).
     */
    public static function encodeB64Url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    /**
     * Decode segmen base64url secara ketat (fail-closed).
     *
     * Menolak string kosong, karakter di luar alfabet base64url, panjang
     * yang mustahil valid (mod 4 === 1), dan hasil decode strict yang gagal.
     *
     * @return string|null Null bila input tidak valid.
     */
    public static function decodeB64Url(string $encoded): ?string
    {
        if ($encoded === '' || preg_match('/^[A-Za-z0-9_-]+$/', $encoded) !== 1) {
            return null;
        }
        if (strlen($encoded) % 4 === 1) {
            return null;
        }
        $std = strtr($encoded, '-_', '+/');
        $padded = $std . str_repeat('=', (4 - strlen($std) % 4) % 4);
        $raw = base64_decode($padded, true);
        return $raw === false ? null : $raw;
    }
}
