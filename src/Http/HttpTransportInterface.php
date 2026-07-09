<?php
declare(strict_types=1);

namespace SecurePayload\Http;

/**
 * Abstraksi pengiriman HTTP untuk helper client `send()` / `sendFile()`.
 */
interface HttpTransportInterface
{
    /**
     * @param array<string,string> $headers
     *
     * @return array{status:int, headers:array<string,string>, body:mixed, error:?string}
     */
    public function send(string $url, string $method, string $body, array $headers): array;
}
