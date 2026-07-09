<?php

declare(strict_types=1);

namespace SecurePayload\Protocol;

/**
 * Utilitas kanonisasi path dan query string untuk protokol SecurePayload.
 */
final class Canonical
{
    /**
     * Normalisasi path URL.
     * Pastikan selalu diawali '/' dan tidak diakhiri '/' (kecuali root).
     */
    public static function normalizePath(string $path): string
    {
        if ($path === '') {
            return '/';
        }
        $path = '/' . ltrim($path, '/');
        if (strlen($path) > 1) {
            $path = rtrim($path, '/');
        }
        return $path;
    }

    /**
     * Canonicalisasi Query String.
     * Urutkan key secara ASC, lalu bangun string query ter-encode.
     *
     * @param array<string,mixed> $q
     */
    public static function canonicalQuery(array $q): string
    {
        if (!$q) {
            return '';
        }
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
}
