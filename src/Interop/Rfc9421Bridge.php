<?php

declare(strict_types=1);

namespace SecurePayload\Interop;

use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\SecurePayload;

/**
 * Jembatan RFC 9421 HTTP Message Signatures ↔ header SecurePayload (hmac-sha256).
 *
 * Export memetakan header SP ke Signature-Input / Signature / Content-Digest.
 * Verify memvalidasi Content-Digest + komponen wajib, lalu mendelegasikan ke SecurePayload::verify().
 */
final class Rfc9421Bridge
{
    public const SIG_LABEL = 'sp1';

    /**
     * Ekspor header SecurePayload ke header RFC 9421 (Signature-Input, Signature, Content-Digest).
     *
     * @param array<string,string> $spHeaders
     * @return array<string,string>
     */
    public static function exportFromSecureHeaders(
        array $spHeaders,
        string $method,
        string $path,
        string $query,
        string $body
    ): array {
        $norm = self::normalize($spHeaders);
        $sig = $norm['X-SIGNATURE'] ?? '';
        if ($sig === '') {
            throw new SecurePayloadException(
                'X-Signature wajib untuk ekspor RFC 9421',
                SecurePayloadException::BAD_REQUEST
            );
        }

        $digestB64 = base64_encode(hash('sha256', $body, true));
        $contentDigest = 'sha-256=:' . $digestB64 . ':';

        $components = ['"@method"', '"@path"', '"@query"', '"content-digest"'];
        $params = [];
        if (($norm['X-CLIENT-ID'] ?? '') !== '') {
            $components[] = '"x-client-id"';
            $params['x-client-id'] = $norm['X-CLIENT-ID'];
        }
        if (($norm['X-KEY-ID'] ?? '') !== '') {
            $components[] = '"x-key-id"';
            $params['x-key-id'] = $norm['X-KEY-ID'];
        }

        $created = (int) ($norm['X-TIMESTAMP'] ?? time());
        $keyid = $norm['X-KEY-ID'] ?? 'default';
        $inner = '(' . implode(' ', $components) . ');created=' . $created . ';keyid="' . $keyid . '";alg="hmac-sha256"';
        $signatureInput = self::SIG_LABEL . '=' . $inner;

        $out = [
            'Signature-Input' => $signatureInput,
            'Signature' => self::SIG_LABEL . '=:' . $sig . ':',
            'Content-Digest' => $contentDigest,
        ];

        // Pertahankan identitas SP agar verifyMapped bisa memetakan balik.
        foreach (['X-Client-Id', 'X-Key-Id', 'X-Timestamp', 'X-Nonce', 'X-Signature-Version',
            'X-Signature-Algorithm', 'X-Signature', 'X-Body-Digest', 'X-Canonical-Request',
            'X-AEAD-Algorithm', 'X-AEAD-Nonce'] as $h) {
            $u = strtoupper($h);
            if (isset($norm[$u]) && $norm[$u] !== '') {
                $out[$h] = $norm[$u];
            }
        }

        return $out;
    }

    /**
     * Verifikasi request yang membawa Signature-Input RFC 9421 dengan memetakan ke SecurePayload::verify().
     *
     * @param array<string,string> $httpHeaders
     * @param array<string,mixed>|string $query
     * @return array{ok:bool,status?:int,error?:string,debug?:array<string,mixed>,mode?:string,bodyPlain?:string,json?:mixed}
     */
    public static function verifyMapped(
        SecurePayload $server,
        array $httpHeaders,
        string $rawBody,
        string $method,
        string $path,
        $query
    ): array {
        $norm = self::normalize($httpHeaders);
        $sigInput = $norm['SIGNATURE-INPUT'] ?? '';

        if ($sigInput === '') {
            // Tanpa Signature-Input: fallback langsung ke verify SP.
            return $server->verify($httpHeaders, $rawBody, $method, $path, $query);
        }

        // Fail-closed: komponen wajib harus ada di Signature-Input.
        $required = ['"@method"', '"@path"', '"@query"', '"content-digest"'];
        foreach ($required as $comp) {
            if (stripos($sigInput, $comp) === false) {
                return [
                    'ok' => false,
                    'status' => SecurePayloadException::BAD_REQUEST,
                    'error' => 'Signature-Input kekurangan komponen wajib: ' . $comp,
                    'debug' => ['missing' => $comp],
                    'mode' => '',
                    'bodyPlain' => '',
                    'json' => null,
                ];
            }
        }

        $contentDigest = $norm['CONTENT-DIGEST'] ?? '';
        $expected = 'sha-256=:' . base64_encode(hash('sha256', $rawBody, true)) . ':';
        if ($contentDigest === '' || !hash_equals($expected, $contentDigest)) {
            return [
                'ok' => false,
                'status' => SecurePayloadException::UNPROCESSABLE,
                'error' => 'Content-Digest tidak cocok dengan body',
                'debug' => ['expected' => $expected, 'got' => $contentDigest],
                'mode' => '',
                'bodyPlain' => '',
                'json' => null,
            ];
        }

        // Petakan identitas dari Signature-Input / header HTTP ke header SP jika perlu.
        $spHeaders = $httpHeaders;
        if (empty(self::normalize($spHeaders)['X-CLIENT-ID']) && preg_match('/"x-client-id"/i', $sigInput)) {
            // Nilai biasanya ada di header HTTP x-client-id
            foreach ($httpHeaders as $k => $v) {
                if (strtoupper($k) === 'X-CLIENT-ID') {
                    $spHeaders['X-Client-Id'] = $v;
                }
            }
        }
        if (empty(self::normalize($spHeaders)['X-KEY-ID'])) {
            foreach ($httpHeaders as $k => $v) {
                if (strtoupper($k) === 'X-KEY-ID') {
                    $spHeaders['X-Key-Id'] = $v;
                }
            }
        }

        // Ambil signature dari header Signature RFC jika X-Signature belum ada.
        $n2 = self::normalize($spHeaders);
        if (($n2['X-SIGNATURE'] ?? '') === '' && isset($norm['SIGNATURE'])) {
            if (preg_match('/' . preg_quote(self::SIG_LABEL, '/') . '=:([^:]+):/', $norm['SIGNATURE'], $m)) {
                $spHeaders['X-Signature'] = $m[1];
            }
        }

        return $server->verify($spHeaders, $rawBody, $method, $path, $query);
    }

    /**
     * @param array<string,string> $headers
     * @return array<string,string>
     */
    private static function normalize(array $headers): array
    {
        $out = [];
        foreach ($headers as $k => $v) {
            $out[strtoupper((string) $k)] = (string) $v;
        }
        return $out;
    }
}
