<?php

declare(strict_types=1);

namespace SecurePayload\Protocol;

/**
 * Utilitas digest dan nonce untuk protokol SecurePayload.
 */
final class Digest
{
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
}
