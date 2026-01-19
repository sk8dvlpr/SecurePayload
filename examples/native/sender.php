<?php
declare(strict_types=1);

/**
 * Contoh Pengirim Native PHP (Tanpa Framework)
 * --------------------------------------------
 * Menggunakan ekstensi cURL bawaan PHP untuk mengirim request aman.
 */

require __DIR__ . '/../../vendor/autoload.php';

use SecurePayload\SecurePayload;

// 1. Konfigurasi Client
$apiKey = 'client_abc';
$keyId = 'key_123';
$hmacSecret = hex2bin('6d657261687075746968...'); // Contoh 32 bytes hex
$aeadKey = '...base64 key...';

$sp = new SecurePayload([
    'mode' => 'both',
    'version' => '1',
    'clientId' => $apiKey,
    'keyId' => $keyId,
    'hmacSecretRaw' => $hmacSecret,
    'aeadKeyB64' => $aeadKey
]);

// 2. Siapkan Data
$targetUrl = 'http://localhost/SecurePayload/examples/native/index.php';
$payload = [
    'user_id' => 101,
    'action' => 'transfer',
    'amount' => 50000
];

// 3. Bangun Header & Body Terenkripsi
// Helper ini melakukan canonicalization, signature, dan encryption (sesuai 'mode')
[$headers, $secureBody] = $sp->buildHeadersAndBody($targetUrl, 'POST', $payload);

// 4. Konversi Header array map ke format CURL (e.g. "Name: Value")
$curlHeaders = [];
foreach ($headers as $k => $v) {
    $curlHeaders[] = "$k: $v";
}

// 5. Kirim dengan cURL
$ch = curl_init($targetUrl);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $secureBody);
curl_setopt($ch, CURLOPT_HTTPHEADER, $curlHeaders);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo 'Error CURL: ' . curl_error($ch);
} else {
    echo "HTTP Status: $httpCode\n";
    echo "Response: $response\n";
}

curl_close($ch);
