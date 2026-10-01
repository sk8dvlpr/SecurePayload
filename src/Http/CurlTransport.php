<?php
declare(strict_types=1);

namespace SecurePayload\Http;

use SecurePayload\Exceptions\SecurePayloadException;

final class CurlTransport implements HttpTransportInterface
{
    private int $timeout;
    private int $connectTimeout;
    private bool $requireHttps;

    /**
     * @param int  $timeout        CURLOPT_TIMEOUT (detik); 0 = tanpa batas (tidak disarankan).
     * @param int  $connectTimeout CURLOPT_CONNECTTIMEOUT (detik).
     * @param bool $requireHttps   Tolak skema non-https (default true).
     */
    public function __construct(int $timeout = 30, int $connectTimeout = 10, bool $requireHttps = false)
    {
        $this->timeout = $timeout;
        $this->connectTimeout = $connectTimeout;
        $this->requireHttps = $requireHttps;
    }

    public function send(string $url, string $method, string $body, array $headers): array
    {
        if (!extension_loaded('curl')) {
            throw new SecurePayloadException('Ekstensi cURL diperlukan', SecurePayloadException::SERVER_ERROR);
        }

        $scheme = strtolower((string) (parse_url($url, PHP_URL_SCHEME) ?? ''));
        if ($this->requireHttps && $scheme !== 'https') {
            throw new SecurePayloadException(
                'CurlTransport mewajibkan URL https:// (skema ditolak: ' . ($scheme !== '' ? $scheme : '(kosong)') . ')',
                SecurePayloadException::BAD_REQUEST
            );
        }
        if ($scheme !== 'https' && $scheme !== 'http') {
            throw new SecurePayloadException(
                'Skema URL tidak diizinkan (hanya http/https): ' . ($scheme !== '' ? $scheme : '(kosong)'),
                SecurePayloadException::BAD_REQUEST
            );
        }

        $outHeaders = [];
        foreach ($headers as $k => $v) {
            $outHeaders[] = $k . ': ' . $v;
        }
        $outHeaders[] = 'Content-Type: application/json';

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $outHeaders);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->connectTimeout);
        // Tolak file://, gopher://, dll. (SSRF surface).
        if (defined('CURLPROTO_HTTP') && defined('CURLPROTO_HTTPS')) {
            $protos = CURLPROTO_HTTP | CURLPROTO_HTTPS;
            curl_setopt($ch, CURLOPT_PROTOCOLS, $protos);
            curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, $protos);
        }
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);

        $resp = curl_exec($ch);
        $err = $resp === false ? curl_error($ch) : null;
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        // curl_close() deprecated di PHP 8.5 — CurlHandle dibebaskan otomatis.

        $rawHeaders = substr((string) $resp, 0, $headerSize);
        $bodyStr = substr((string) $resp, $headerSize);

        return HttpResponseParser::fromParts(
            $code,
            HttpResponseParser::parseHeaderBlock($rawHeaders),
            $bodyStr,
            $err
        );
    }
}
