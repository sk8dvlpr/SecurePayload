<?php
declare(strict_types=1);
/**
 * Contoh server native PHP dengan exporter Prometheus (Phase 15).
 *
 * Jalankan: php -S localhost:8080 examples/observability/prometheus.php
 * Metrics: GET http://localhost:8080/metrics
 * API:     POST http://localhost:8080/v1/pay (body + header SecurePayload)
 */
require dirname(__DIR__, 2) . '/vendor/autoload.php';

use SecurePayload\KMS\EnvKeyProvider;
use SecurePayload\Observability\PrometheusSecurityExporter;
use SecurePayload\SecurePayload;

$exporter = new PrometheusSecurityExporter([
    // 'includeClientId' => true, // hati-hati cardinality tinggi di produksi
]);

$provider = new EnvKeyProvider();
$server = new SecurePayload([
    'mode' => 'both',
    'version' => '3',
    'keyLoader' => static fn (string $cid, string $kid): array => $provider->load($cid, $kid),
    'onSecurityEvent' => $exporter->onSecurityEvent(),
]);

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

if ($path === '/metrics') {
    header('Content-Type: text/plain; version=0.0.4; charset=utf-8');
    echo $exporter->render();
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$rawBody = (string) file_get_contents('php://input');
$result = $server->verify(
    getallheaders() ?: [],
    $rawBody,
    $_SERVER['REQUEST_METHOD'],
    $path,
    $_GET
);

if (!$result['ok']) {
    http_response_code((int) ($result['status'] ?? 401));
    echo json_encode(['error' => $result['error'] ?? 'unauthorized']);
    exit;
}

header('Content-Type: application/json');
echo json_encode(['ok' => true, 'data' => $result['json']]);
