<?php
declare(strict_types=1);

/**
 * Contoh PENERIMA transfer file streaming (Phase 6).
 *
 * 1. Verifikasi MANIFEST lewat jalur request aman biasa (`verify()`).
 * 2. Dekripsi file ciphertext per-chunk ke file plaintext via `verifyFileStream()`,
 *    yang juga menegakkan batas ukuran, allow/block ekstensi, dan strict MIME.
 *
 * `verifyFileStream()` GAGAL-TERTUTUP: bila verifikasi gagal, file plaintext
 * parsial otomatis dihapus.
 */

use SecurePayload\SecurePayload;

$sp = new SecurePayload([
    'mode' => 'both',
    // Untuk multi-client, muat kunci klien terkait (mis. EnvKeyProvider/DbKeyProvider)
    // dan set instance ini dengan aeadKeyB64 + hmacSecretRaw klien tersebut.
    'aeadKeyB64' => getenv('SP_AEAD_B64') ?: base64_encode(str_repeat('k', 32)),
    'keyLoader' => fn($cid, $kid) => [
        'hmacSecret' => getenv('SP_HMAC') ?: str_repeat('x', 32),
        'aeadKeyB64' => getenv('SP_AEAD_B64') ?: base64_encode(str_repeat('k', 32)),
    ],
    // 'deriveKeys' => true, // harus cocok dengan pengirim
]);

// --- 1. Verifikasi manifest (request aman) ---
$headers = function_exists('getallheaders') ? getallheaders() : [];
$rawBody = file_get_contents('php://input') ?: '';
$res = $sp->verify($headers, $rawBody, $_SERVER['REQUEST_METHOD'] ?? 'POST', '/upload/manifest', $_GET ?? []);
if (!($res['ok'] ?? false)) {
    http_response_code($res['status'] ?? 401);
    echo json_encode(['error' => $res['error'] ?? 'unauthorized']);
    return;
}
/** @var array<string,mixed> $manifest */
$manifest = $res['json'];

// --- 2. Dekripsi & validasi file ciphertext (di-upload terpisah) ---
$cipherPath = '/path/ke/blob-yang-diunggah.sps';
$plainPath = sys_get_temp_dir() . '/decrypted-' . bin2hex(random_bytes(6));

$fileRes = $sp->verifyFileStream($cipherPath, $manifest, $plainPath, [
    'max_size' => 100 * 1024 * 1024,        // 100 MB
    'allowed_exts' => ['zip', 'pdf', 'png'],
    'strict_mime' => true,
]);

if (!($fileRes['ok'] ?? false)) {
    http_response_code($fileRes['status'] ?? 422);
    echo json_encode(['error' => $fileRes['error'] ?? 'file invalid']);
    return;
}

// Sukses: file plaintext aman tersedia di $fileRes['file']['path'].
echo json_encode(['ok' => true, 'file' => $fileRes['file']]);
