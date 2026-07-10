<?php

declare(strict_types=1);

/**
 * Contoh jembatan RFC 9421 ↔ SecurePayload.
 *
 * Jalankan: php examples/interop/rfc9421.php
 */

require dirname(__DIR__, 2) . '/vendor/autoload.php';

use SecurePayload\Interop\Rfc9421Bridge;
use SecurePayload\SecurePayload;

$secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
$clock = static fn (): int => 1_700_000_000;

$client = new SecurePayload([
    'mode' => 'hmac',
    'version' => '3',
    'clientId' => 'demo-client',
    'keyId' => 'demo-key',
    'hmacSecretRaw' => $secret,
    'clock' => $clock,
    'nonceGenerator' => static fn (): string => base64_encode(str_repeat("\x01", 16)),
]);

$server = new SecurePayload([
    'mode' => 'hmac',
    'version' => '3',
    'clock' => $clock,
    'replayStore' => static fn (string $k, int $t): bool => true,
    'keyLoader' => static fn (): array => ['hmacSecret' => $secret, 'aeadKeyB64' => null],
]);

[$spHeaders, $body] = $client->buildHeadersAndBody(
    'https://api.example.com/v1/hook?x=1',
    'POST',
    ['event' => 'ping']
);

$rfc = Rfc9421Bridge::exportFromSecureHeaders(
    $spHeaders,
    'POST',
    '/v1/hook',
    'x=1',
    $body
);

echo "=== Export RFC 9421 ===\n";
foreach ($rfc as $k => $v) {
    echo "$k: $v\n";
}

$result = Rfc9421Bridge::verifyMapped(
    $server,
    $rfc,
    $body,
    'POST',
    '/v1/hook',
    'x=1'
);

echo "\n=== verifyMapped ===\n";
echo $result['ok'] ? "OK\n" : ('FAIL: ' . ($result['error'] ?? '') . "\n");
if ($result['ok']) {
    echo 'json: ' . json_encode($result['json']) . "\n";
}
