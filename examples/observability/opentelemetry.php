<?php
declare(strict_types=1);
/**
 * Contoh integrasi OpenTelemetry (Phase 17).
 *
 * Tanpa paket open-telemetry/sdk terpasang, exporter beroperasi no-op.
 * Pasang tracer nyata dari SDK OpenTelemetry PHP bila tersedia.
 *
 * Jalankan: php -S localhost:8080 examples/observability/opentelemetry.php
 */
require dirname(__DIR__, 2) . '/vendor/autoload.php';

use SecurePayload\KMS\EnvKeyProvider;
use SecurePayload\Observability\OpenTelemetrySecurityExporter;
use SecurePayload\Observability\PrometheusSecurityExporter;
use SecurePayload\SecurePayload;
use SecurePayload\Webhook\WebhookVerifier;

$otel = new OpenTelemetrySecurityExporter([
    // 'tracer' => $tracer, // dari OpenTelemetry SDK
]);
$prom = new PrometheusSecurityExporter();

$onSecurityEvent = static function (string $event, array $context) use ($otel, $prom): void {
    ($otel->onSecurityEvent())($event, $context);
    ($prom->onSecurityEvent())($event, $context);
};

$provider = new EnvKeyProvider();
$server = new SecurePayload([
    'mode' => 'both',
    'version' => '3',
    'keyLoader' => static fn (string $cid, string $kid): array => $provider->load($cid, $kid),
    'onSecurityEvent' => $onSecurityEvent,
]);

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
if ($path === '/metrics') {
    header('Content-Type: text/plain; version=0.0.4; charset=utf-8');
    echo $prom->render();
    exit;
}

$verifier = new WebhookVerifier($server);
$rawBody = (string) file_get_contents('php://input');
$span = $otel->startVerifySpan();
$result = $verifier->verifyFromGlobals($_SERVER, $rawBody);
$otel->endVerifySpan($span, (bool) ($result['ok'] ?? false));

header('Content-Type: application/json');
if (!$result['ok']) {
    http_response_code((int) ($result['status'] ?? 401));
    echo json_encode(['error' => $result['error'] ?? 'unauthorized']);
    exit;
}

echo json_encode(['ok' => true, 'data' => $result['json']]);
