<?php
declare(strict_types=1);
/**
 * Contoh webhook receiver native PHP (Phase 17).
 *
 * Jalankan: php -S localhost:8080 examples/webhook/verify.php
 */
require dirname(__DIR__, 2) . '/vendor/autoload.php';

use SecurePayload\KMS\EnvKeyProvider;
use SecurePayload\Webhook\WebhookVerifier;
use SecurePayload\SecurePayload;

$provider = new EnvKeyProvider();
$server = new SecurePayload([
    'mode' => 'both',
    'version' => '3',
    'keyLoader' => static fn (string $cid, string $kid): array => $provider->load($cid, $kid),
]);

$verifier = new WebhookVerifier($server);
$rawBody = (string) file_get_contents('php://input');
$result = $verifier->verifyFromGlobals($_SERVER, $rawBody);

header('Content-Type: application/json');
if (!$result['ok']) {
    http_response_code((int) ($result['status'] ?? 401));
    echo json_encode(['error' => $result['error'] ?? 'unauthorized']);
    exit;
}

echo json_encode(['ok' => true, 'data' => $result['json']]);
