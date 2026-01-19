<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Integration;

use PDO;
use PHPUnit\Framework\TestCase;
use SecurePayload\KMS\DbKeyProvider;
use SecurePayload\KMS\KeyManager;
use SecurePayload\KMS\LocalKms;
use SecurePayload\SecurePayload;

class MultiClientTest extends TestCase
{
    private PDO $pdo;
    private LocalKms $kms;
    private string $kekId;

    protected function setUp(): void
    {
        // 1. Setup KMS (Mock Env)
        $this->kekId = 'test_master_key';
        $kekRaw = random_bytes(32);
        putenv("SECURE_KEKS={$this->kekId}");
        putenv("SECURE_KEK_{$this->kekId}_B64=" . base64_encode($kekRaw));

        $this->kms = LocalKms::fromEnv();

        // 2. Setup SQLite DB
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Buat tabel penyimpanan kunci
        $this->pdo->exec("CREATE TABLE secure_keys (
            client_id TEXT PRIMARY KEY,
            key_id TEXT,
            hmac_secret TEXT,
            aead_key_b64 TEXT,
            wrapped_b64 TEXT,
            kek_id TEXT
        )");
    }

    public function testMultiClientSupport(): void
    {
        // --- PREPARATION: GENERATE KEYS FOR 2 DIFFERENT CLIENTS ---
        $manager = new KeyManager($this->kms);

        // Client A
        $credsA = $manager->generateKeyPair('client_A', 'key_A', $this->kekId);
        $this->pdo->exec($credsA->toSqlInsert('secure_keys'));

        // Client B
        $credsB = $manager->generateKeyPair('client_B', 'key_B', $this->kekId);
        $this->pdo->exec($credsB->toSqlInsert('secure_keys'));

        // Setup Server with DbKeyProvider
        $server = new SecurePayload([
            'mode' => 'both', // Enforce Encryption + Signature
            'version' => '1',
            'keyLoader' => [new DbKeyProvider($this->pdo, [], $this->kms), 'load']
        ]);


        // --- SCENARIO 1: Client A sends valid request ---
        $clientA = new SecurePayload([
            'mode' => 'both',
            'version' => '1',
            'clientId' => $credsA->clientId,
            'keyId' => $credsA->keyId,
            // Perbaikan: Gunakan string HEX langsung karena DB menyimpan HEX.
            // Client harus menggunakan key yang SAMA PERSIS dengan yang diload Server dari DB.
            'hmacSecretRaw' => $credsA->hmacSecret,
            'aeadKeyB64' => $credsA->aeadKeyB64
        ]);

        $payloadA = ['msg' => 'Hello from A'];
        [$headersA, $bodyA] = $clientA->buildHeadersAndBody('https://api.test/resource', 'POST', $payloadA);

        // Server verifying A
        $resA = $server->verify($headersA, $bodyA, 'POST', '/resource', []);

        // Debugging info in case of failure
        if (!$resA['ok']) {
            fwrite(STDERR, "\nDEBUG Failure A: " . json_encode($resA, JSON_PRETTY_PRINT) . "\n");
        }

        $this->assertTrue($resA['ok']);
        $this->assertSame('BOTH', $resA['mode']);
        $this->assertSame($payloadA, $resA['json']);


        // --- SCENARIO 2: Client B sends valid request ---
        $clientB = new SecurePayload([
            'mode' => 'both',
            'version' => '1',
            'clientId' => $credsB->clientId,
            'keyId' => $credsB->keyId,
            'hmacSecretRaw' => $credsB->hmacSecret, // Use Hex string directly
            'aeadKeyB64' => $credsB->aeadKeyB64
        ]);

        $payloadB = ['msg' => 'Hello from B'];
        [$headersB, $bodyB] = $clientB->buildHeadersAndBody('https://api.test/resource', 'POST', $payloadB);

        // Server verifying B
        $resB = $server->verify($headersB, $bodyB, 'POST', '/resource', []);
        $this->assertTrue($resB['ok']);
        $this->assertSame($payloadB, $resB['json']);


        // --- SCENARIO 3: Cross-Client Attack (Spoofing) ---
        // Client A signs a message, but sends Client B's ID in header?
        // Logic: SecurePayload verify() trusts header ID to load key. 
        // If I send Client B ID, server loads Key B.
        // But I signed with Key A. Signature validation MUST fail.

        $headersSpoof = $headersA;
        $headersSpoof['X-Client-Id'] = 'client_B';
        $headersSpoof['X-Key-Id'] = 'key_B'; // Must match DB lookup for B

        $resSpoof = $server->verify($headersSpoof, $bodyA, 'POST', '/resource', []);

        $this->assertFalse($resSpoof['ok'], 'Server should reject spoofed client ID (Signature mismatch)');
    }
}
