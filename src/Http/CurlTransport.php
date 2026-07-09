<?php
declare(strict_types=1);

namespace SecurePayload\Http;

use SecurePayload\Exceptions\SecurePayloadException;

final class CurlTransport implements HttpTransportInterface
{
    public function send(string $url, string $method, string $body, array $headers): array
    {
        if (!extension_loaded('curl')) {
            throw new SecurePayloadException('Ekstensi cURL diperlukan', SecurePayloadException::SERVER_ERROR);
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

        $resp = curl_exec($ch);
        $err = $resp === false ? curl_error($ch) : null;
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);

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
