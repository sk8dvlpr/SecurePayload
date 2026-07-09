<?php
declare(strict_types=1);
require dirname(__DIR__, 4) . '/vendor/autoload.php';

use SecurePayload\SecurePayload;

$in = json_decode((string) stream_get_contents(STDIN), true);
$keys = json_decode((string) file_get_contents(dirname(__DIR__, 4) . '/docs/fixtures/v3/keys/standard.json'), true);
$sp = new SecurePayload([
  'mode' => 'both',
  'version' => '3',
  'signAlg' => 'hmac',
  'clock' => static fn (): int => 1700000000,
  'replayStore' => static fn (string $k, int $ttl): bool => true,
  'keyLoader' => static fn (string $cid, string $kid): array => [
    'hmacSecret' => $keys['hmacSecret'],
    'aeadKeyB64' => $keys['aeadKeyB64'],
  ],
]);
$out = $sp->verify($in['headers'], $in['body'], 'POST', '/v1/pay', ['a' => '1', 'b' => '2']);
echo json_encode($out);
