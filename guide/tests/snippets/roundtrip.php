<?php
declare(strict_types=1);

/**
 * Minimal both-mode build+verify roundtrip with random TEST keys.
 * Asserts successful verify and that tampering fails.
 *
 * Run from repo root: php guide/tests/snippets/roundtrip.php
 */

$autoload = dirname(__DIR__, 3) . '/vendor/autoload.php';
if (!is_file($autoload)) {
    fwrite(STDERR, "vendor/autoload.php missing - run composer install\n");
    exit(1);
}
require $autoload;

use SecurePayload\SecurePayload;

if (!extension_loaded('sodium')) {
    fwrite(STDERR, "ext-sodium required for both mode\n");
    exit(1);
}

$hmac = bin2hex(random_bytes(16)); // 32 chars
$aead = base64_encode(random_bytes(32));

$client = new SecurePayload([
    'mode' => 'both',
    'clientId' => 'guide-test',
    'keyId' => 'v1',
    'hmacSecretRaw' => $hmac,
    'aeadKeyB64' => $aead,
]);

$server = new SecurePayload([
    'mode' => 'both',
    'keyLoader' => static function (string $cid, string $kid) use ($hmac, $aead): array {
        return [
            'hmacSecret' => $hmac,
            'aeadKeyB64' => $aead,
        ];
    },
]);

$url = 'https://example.test/api/guide-roundtrip';
$method = 'POST';
$path = '/api/guide-roundtrip';
$query = '';
$payload = ['ok' => true, 'n' => random_int(1, 9999)];

[$headers, $body] = $client->buildHeadersAndBody($url, $method, $payload);

$result = $server->verify($headers, $body, $method, $path, $query);
if (empty($result['ok'])) {
    fwrite(STDERR, 'VERIFY FAILED: ' . json_encode($result, JSON_UNESCAPED_UNICODE) . "\n");
    exit(1);
}

$tampered = $body . 'x';
$bad = $server->verify($headers, $tampered, $method, $path, $query);
if (!empty($bad['ok'])) {
    fwrite(STDERR, "TAMPER SHOULD FAIL but verify returned ok\n");
    exit(1);
}

echo "roundtrip OK (both mode); tamper rejected\n";
exit(0);
