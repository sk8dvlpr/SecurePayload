<?php

declare(strict_types=1);

namespace SecurePayload\Webhook;

use SecurePayload\SecurePayload;

/**
 * Helper verifikasi request webhook (raw body + header HTTP).
 *
 * Method/path/query diturunkan dari input server — BUKAN dari header keamanan SecurePayload.
 */
final class WebhookVerifier
{
    public function __construct(
        private SecurePayload $server,
    ) {
    }

    /**
     * Verifikasi dari superglobal PHP (`$_SERVER`) dan body mentah.
     *
     * @param array<string,mixed> $serverGlobals Biasanya `$_SERVER`
     * @param callable(): array<string,string>|null $headerReader Callable pembaca header; default nginx/fpm fallback
     *
     * @return array{ok:bool, status?:int, error?:string, debug?:array<string,mixed>, mode?:string, bodyPlain?:string, json?:mixed}
     */
    public function verifyFromGlobals(array $serverGlobals, string $rawBody, ?callable $headerReader = null): array
    {
        $method = (string) ($serverGlobals['REQUEST_METHOD'] ?? 'GET');
        $uri = (string) ($serverGlobals['REQUEST_URI'] ?? '/');
        $path = parse_url($uri, PHP_URL_PATH);
        $query = parse_url($uri, PHP_URL_QUERY);
        if (!is_string($path) || $path === '') {
            $path = '/';
        }

        $headers = $headerReader !== null ? ($headerReader() ?? []) : self::readHeadersFromServer($serverGlobals);

        return $this->verifyFromRequest($headers, $rawBody, $method, $path, is_string($query) ? $query : '');
    }

    /**
     * Verifikasi dari komponen request eksplisit.
     *
     * @param array<string,string> $headers
     * @param array<string,mixed>|string $query
     *
     * @return array{ok:bool, status?:int, error?:string, debug?:array<string,mixed>, mode?:string, bodyPlain?:string, json?:mixed}
     */
    public function verifyFromRequest(array $headers, string $rawBody, string $method, string $path, array|string $query = []): array
    {
        return $this->server->verify($headers, $rawBody, $method, $path, $query);
    }

    /**
     * Baca header HTTP dari `$_SERVER` (kompatibel nginx/PHP-FPM tanpa getallheaders()).
     *
     * @param array<string,mixed> $serverGlobals
     *
     * @return array<string,string>
     */
    public static function readHeadersFromServer(array $serverGlobals): array
    {
        if (function_exists('getallheaders')) {
            $fromFn = getallheaders();
            if (is_array($fromFn) && $fromFn !== []) {
                $out = [];
                foreach ($fromFn as $k => $v) {
                    if (is_string($k)) {
                        $out[$k] = (string) $v;
                    }
                }
                return $out;
            }
        }

        $headers = [];
        foreach ($serverGlobals as $key => $value) {
            if (!is_string($key) || !is_scalar($value)) {
                continue;
            }
            if (str_starts_with($key, 'HTTP_')) {
                $headerName = str_replace('_', '-', substr($key, 5));
                $headers[$headerName] = (string) $value;
            }
        }
        if (isset($serverGlobals['CONTENT_TYPE'])) {
            $headers['Content-Type'] = (string) $serverGlobals['CONTENT_TYPE'];
        }
        if (isset($serverGlobals['CONTENT_LENGTH'])) {
            $headers['Content-Length'] = (string) $serverGlobals['CONTENT_LENGTH'];
        }

        return $headers;
    }
}
