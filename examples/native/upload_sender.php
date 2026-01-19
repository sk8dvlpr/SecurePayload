<?php
// examples/native/upload_sender.php
require __DIR__ . '/../../vendor/autoload.php';

use SecurePayload\SecurePayload;

$client = new SecurePayload([
    'mode' => 'both',
    'clientId' => 'client_native',
    'keyId' => 'key_v1',
    'hmacSecretRaw' => hex2bin('beefcafebabe0000000000000000000000000000000000000000000000000000'),
    'aeadKeyB64' => base64_encode('0123456789abcdef0123456789abcdef')
]);

// Buat dummy file untuk demo
$tmpFile = sys_get_temp_dir() . '/dummy_secure.txt';
file_put_contents($tmpFile, 'Ini adalah file rahasia yang dikirim via SecurePayload!');

try {
    echo "Uploading file: $tmpFile\n";

    // Kirim menggunakan helper sendFile
    $result = $client->sendFile(
        'http://localhost:8000/examples/native/upload_receiver.php', // Sesuaikan URL
        'POST',
        $tmpFile,
        ['keterangan' => 'Dokumen Sangat Rahasia', 'priority' => 'high'], // Metadata tambahan
        'rahasia.txt' // Rename file saat diterima server
    );

    echo "Status: " . $result['status'] . "\n";
    echo "Response: \n";
    print_r($result['body']);

} catch (Exception $e) {
    echo "Error: " . $e->getMessage();
}

// Cleanup
@unlink($tmpFile);
