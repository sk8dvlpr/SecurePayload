<?php
declare(strict_types=1);
require dirname(__DIR__, 4) . '/vendor/autoload.php';

use SecurePayload\SecurePayload;

$keys = json_decode((string) file_get_contents(dirname(__DIR__, 4) . '/docs/fixtures/v3/keys/standard.json'), true);
$sp = new SecurePayload([
  'mode' => 'both',
  'version' => '3',
  'signAlg' => 'hmac',
  'clientId' => $keys['clientId'],
  'keyId' => $keys['keyId'],
  'hmacSecretRaw' => $keys['hmacSecret'],
  'aeadKeyB64' => $keys['aeadKeyB64'],
  'clock' => static fn (): int => 1700000000,
  'nonceGenerator' => static fn (): string => 'AQEBAQEBAQEBAQEBAQEBAQ==',
]);
[$h, $b] = $sp->buildHeadersAndBody('https://example.test/v1/pay?a=1&b=2', 'POST', ['amount' => 100]);
echo json_encode(['headers' => $h, 'body' => $b]);
