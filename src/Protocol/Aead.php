<?php

declare(strict_types=1);

namespace SecurePayload\Protocol;

/**
 * Utilitas AEAD: AAD, nonce derivasi, dan binding konteks request/response.
 */
final class Aead
{
    public static function buildRequestAeadAad(string $version, string $ts, array $boundHeaders = []): string
    {
        $parts = ['v' . $version, 'ts=' . $ts];
        ksort($boundHeaders);
        foreach ($boundHeaders as $name => $val) {
            $parts[] = 'h:' . $name . '=' . $val;
        }
        return implode("\n", $parts);
    }

    /**
     * AAD untuk enkripsi RESPONSE (publik untuk spesifikasi / conformance).
     */
    public static function buildResponseAeadAad(string $version, string $reqNonceB64, string $respTs): string
    {
        return 'resp-v' . $version . '|req=' . $reqNonceB64 . '|ts=' . $respTs;
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
        $msg = implode("\n", [strtoupper($method), Canonical::normalizePath($path), (string) $qStr, $seed]);

        // Hash jadi 32 byte -> potong sesuai kebutuhan algoritma (biasanya 24 byte untuk XChaCha20)
        $h = hash('sha256', $msg, true);

        $len = defined('SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES')
            ? (int) SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
            : 24;

        return substr($h, 0, $len);
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
}
