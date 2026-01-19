<?php
declare(strict_types=1);

/**
 * Contoh Implementasi Native PHP (Tanpa Framework)
 * ------------------------------------------------
 * Contoh ini menunjukkan cara mengintegrasikan SecurePayload di script PHP mentah.
 * Berguna untuk legacy project atau micro-service sederhana.
 */

// 1. Autoload (Pastikan path vendor benar)
require __DIR__ . '/../../vendor/autoload.php';

use SecurePayload\SecurePayload;
use SecurePayload\KMS\EnvKeyProvider;

// 2. Setup Key Provider
// Di native PHP, pastikan variabel ENV sudah diload (misal via dotenv) atau set server env.
// putenv('SECUREPAYLOAD_CLIENT1_KEY1_HMAC_SECRET=...'); 
$provider = new EnvKeyProvider();
$keyLoader = fn(string $cid, string $kid) => $provider->load($cid, $kid);

// 3. Inisialisasi Library
try {
    $sp = new SecurePayload([
        'mode' => 'both', // Enforce Encryption & Signature
        'version' => '1',
        'keyLoader' => $keyLoader,
    ]);
} catch (Exception $e) {
    http_response_code(500);
    die(json_encode(['error' => 'Config Error: ' . $e->getMessage()]));
}

// 4. Ambil Data dari Native Globals ($_SERVER, input stream)
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$uri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url($uri, PHP_URL_PATH);
$query = $_SERVER['QUERY_STRING'] ?? '';

// Ambil Header (function getallheaders() tidak selalu ada di Nginx/FPM, jadi kita manual parse)
$headers = [];
foreach ($_SERVER as $key => $value) {
    if (str_starts_with($key, 'HTTP_')) {
        $headerName = str_replace('_', '-', substr($key, 5));
        $headers[$headerName] = $value;
    }
}
// Tambahan Content-Type/Length yang kadang tidak ber-prefix HTTP_
if (isset($_SERVER['CONTENT_TYPE']))
    $headers['CONTENT-TYPE'] = $_SERVER['CONTENT_TYPE'];
if (isset($_SERVER['CONTENT_LENGTH']))
    $headers['CONTENT-LENGTH'] = $_SERVER['CONTENT_LENGTH'];

// Ambil Body
$body = file_get_contents('php://input') ?: '';

// 5. Verifikasi
try {
    $vr = $sp->verify($headers, $body, $method, $path, $query);

    if (!$vr['ok']) {
        http_response_code($vr['status'] ?? 400);
        header('Content-Type: application/json');
        echo json_encode(['error' => $vr['error']]);
        exit;
    }

    // 6. Sukses
    header('Content-Type: application/json');
    echo json_encode([
        'status' => 'success',
        'message' => 'Request valid!',
        'data' => $vr['json'] // Data yang sudah didekripsi (jika mode AEAD/BOTH)
    ]);

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Internal Error']);
}
