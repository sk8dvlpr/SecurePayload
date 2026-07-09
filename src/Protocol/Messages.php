<?php

declare(strict_types=1);

namespace SecurePayload\Protocol;

/**
 * Pembentukan pesan kanonik untuk tanda tangan HMAC/Ed25519.
 */
final class Messages
{
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
