<?php
require __DIR__ . '/../vendor/autoload.php';

use SecurePayload\KMS\DbKeyProvider;
use SecurePayload\KMS\LocalKms;

// 1. Setup In-Memory SQLite Database
try {
    $pdo = new PDO('sqlite::memory:');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Create Table as expected by DbKeyProvider defaults
    $pdo->exec("CREATE TABLE secure_keys (
        client_id TEXT,
        key_id TEXT,
        hmac_secret TEXT,
        aead_key_b64 TEXT,
        wrapped_b64 TEXT,
        kek_id TEXT
    )");

    echo "[INFO] SQLite table created.\n";

    // 2. Insert Test Data (Plaintext keys)
    $stmt = $pdo->prepare("INSERT INTO secure_keys (client_id, key_id, hmac_secret) VALUES (?, ?, ?)");
    $stmt->execute(['client1', 'key1', 'secret-for-client1']);
    echo "[INFO] Inserted plaintext key for client1.\n";

} catch (Exception $e) {
    die("[ERROR] DB Setup failed: " . $e->getMessage() . "\n");
}

// 3. Test DbKeyProvider (Plaintext)
echo "\n--- Testing DbKeyProvider (Plaintext) ---\n";
try {
    $provider = new DbKeyProvider($pdo); // Use defaults
    $keys = $provider->load('client1', 'key1');

    if ($keys['hmacSecret'] === 'secret-for-client1') {
        echo "[SUCCESS] Loaded plaintext key correctly.\n";
    } else {
        echo "[FAIL] Failed to load key. Got: " . json_encode($keys) . "\n";
    }
} catch (Exception $e) {
    echo "[FAIL] Exception: " . $e->getMessage() . "\n";
}

// 4. Test LocalKms Setup
echo "\n--- Testing LocalKms ---\n";
$kekId = 'master1';
$kekRaw = random_bytes(32);
$kekB64 = base64_encode($kekRaw);

// Simulate Env Vars
putenv("SECURE_KEKS=$kekId");
putenv("SECURE_KEK_{$kekId}_B64=$kekB64");

try {
    $kms = LocalKms::fromEnv();
    echo "[SUCCESS] LocalKms loaded from environment.\n";

    // 5. Test DbKeyProvider with KMS (Wrapped Keys)
    echo "\n--- Testing DbKeyProvider with KMS (Wrapped Key) ---\n";

    // Encrypt a key using KMS to simulate stored wrapped key
    $realAeadKey = random_bytes(32);
    $wrapped = $kms->wrap($kekId, $realAeadKey, [
        'client_id' => 'client2',
        'key_id' => 'key2',
        'purpose' => 'securepayload-aead-key'
    ]);

    // Insert into DB
    $stmt = $pdo->prepare("INSERT INTO secure_keys (client_id, key_id, wrapped_b64, kek_id) VALUES (?, ?, ?, ?)");
    $stmt->execute(['client2', 'key2', $wrapped, $kekId]);

    // Test Load
    $providerWithKms = new DbKeyProvider($pdo, [], $kms);
    $keys2 = $providerWithKms->load('client2', 'key2');

    $loadedAeadB64 = $keys2['aeadKeyB64'];
    $loadedAeadRaw = base64_decode($loadedAeadB64 ?? '');

    if ($loadedAeadRaw === $realAeadKey) {
        echo "[SUCCESS] Unwrapped AEAD key matches original.\n";
    } else {
        echo "[FAIL] Unwrapping failed or mismatch.\n";
    }

} catch (Exception $e) {
    echo "[FAIL] KMS Test failed: " . $e->getMessage() . "\n";
}
