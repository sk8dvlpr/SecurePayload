<?php
declare(strict_types=1);

namespace SecurePayload\Http;

/**
 * Parser response HTTP mentah → struktur return `send()`.
 */
final class HttpResponseParser
{
    /**
     * @return array{status:int, headers:array<string,string>, body:mixed, error:?string}
     */
    public static function fromParts(int $status, array $headers, string $bodyStr, ?string $error = null): array
    {
        $json = json_decode($bodyStr, true);

        return [
            'status' => $status,
            'headers' => $headers,
            'body' => $json !== null ? $json : $bodyStr,
            'error' => $error,
        ];
    }

    /**
     * @return array<string,string>
     */
    public static function parseHeaderBlock(string $rawHeaders): array
    {
        $respHeaders = [];
        foreach (preg_split("/\r?\n/", $rawHeaders) as $line) {
            if (strpos($line, ':') !== false) {
                [$hk, $hv] = array_map('trim', explode(':', $line, 2));
                if ($hk !== '') {
                    $respHeaders[$hk] = $hv;
                }
            }
        }

        return $respHeaders;
    }
}
