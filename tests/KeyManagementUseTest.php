<?php
require __DIR__ . '/../vendor/autoload.php';

use SecurePayload\KMS\DbKeyProvider;
use SecurePayload\KMS\LocalKms;
use SecurePayload\KMS\KeyManager;

// 1. Setup KMS & DB
$kekId = 'master_production';
$kekRaw = random_bytes(32);
$kekB64 = base64_encode($kekRaw);
putenv("SECURE_KEKS=$kekId");
putenv("SECURE_KEK_{$kekId}_B64=$kekB64");

$kms = LocalKms::fromEnv();

$pdo = new PDO('sqlite::memory:');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->exec("CREATE TABLE secure_keys (
    client_id TEXT,
    key_id TEXT,
    hmac_secret TEXT,
    aead_key_b64 TEXT,
    wrapped_b64 TEXT,
    kek_id TEXT
)");

// 2. Gunakan KeyManager untuk membuat credentials baru
$manager = new KeyManager($kms);
$newCreds = $manager->generateKeyPair('client_vip', 'key_2025_v1', $kekId);

echo "--- Key Generated ---\n";
echo "Client ID: " . $newCreds->clientId . "\n";
echo "HMAC Secret: " . $newCreds->hmacSecret . "\n";
echo "AEAD (Wrapped): " . ($newCreds->wrappedKeyB64 ? 'YES' : 'NO') . "\n";

// 3. Insert ke DB menggunakan SQL yang digenerate helper
$sql = $newCreds->toSqlInsert('secure_keys');
echo "SQL: $sql\n";
$pdo->exec($sql);

// 4. Test Load kembali via DbKeyProvider
$provider = new DbKeyProvider($pdo, [], $kms);
$loaded = $provider->load('client_vip', 'key_2025_v1');

if ($loaded['hmacSecret'] === $newCreds->hmacSecret) {
    echo "[PASS] HMAC Secret Loaded correctly.\n";
} else {
    echo "[FAIL] HMAC mismatch.\n";
}

if ($loaded['aeadKeyB64'] === $newCreds->aeadKeyB64) {
    echo "[PASS] AEAD Key unwrapped correctly.\n";
} else {
    echo "[FAIL] AEAD mismatch.\n";
}

// 5. Cleanup
echo "[DONE] Test KeyManager finished.\n";
