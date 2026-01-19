<?php
// examples/native/upload_receiver.php
require __DIR__ . '/../../vendor/autoload.php';

use SecurePayload\SecurePayload;

header('Content-Type: application/json');

// Setup Server credential (Sama dengan sender)
$server = new SecurePayload([
    'mode' => 'both',
    'keyLoader' => function ($cid, $kid) {
        if ($cid === 'client_native' && $kid === 'key_v1') {
            return [
                'hmacSecret' => hex2bin('beefcafebabe0000000000000000000000000000000000000000000000000000'),
                'aeadKeyB64' => base64_encode('0123456789abcdef0123456789abcdef')
            ];
        }
        return null; // Key not found
    }
]);

// Verifikasi File Payload
$result = $server->verifyFilePayload(
    getallheaders(),
    file_get_contents('php://input'),
    $_SERVER['REQUEST_METHOD'],
    parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH),
    [
        'max_size' => 2 * 1024 * 1024, // Limit 2MB
        'allowed_exts' => ['txt', 'pdf', 'jpg'], // Whitelist
        'block_dangerous' => true, // Auto block .php, .exe, etc
        'strict_mime' => true // Deep check mime type
    ]
);

if (!$result['ok']) {
    http_response_code($result['status'] ?? 400);
    echo json_encode(['error' => $result['error']]);
    exit;
}

$file = $result['file'];
$meta = $result['data'];

// Sukses!
// Di sini Anda bisa menyimpan file ke disk, S3, dll.
// $file['content_decoded'] berisi raw binary file asli.

echo json_encode([
    'message' => 'File diterima dengan aman!',
    'file_info' => [
        'name' => $file['name'],
        'size' => $file['size'],
        'mime' => $file['type']
    ],
    'metadata_received' => $meta
]);
