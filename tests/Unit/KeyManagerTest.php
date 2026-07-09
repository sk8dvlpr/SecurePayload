<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\KMS\KeyManager;
use SecurePayload\KMS\LocalKms;
use PDO;

final class KeyManagerTest extends TestCase
{
    private PDO $pdo;
    private array $envBackup = [];

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $this->pdo->exec("
            CREATE TABLE secure_keys (
                client_id VARCHAR(50),
                key_id VARCHAR(50),
                hmac_secret VARCHAR(255),
                aead_key_b64 VARCHAR(255),
                wrapped_b64 VARCHAR(255),
                kek_id VARCHAR(50),
                PRIMARY KEY(client_id, key_id)
            )
        ");

        $this->envBackup = [];
    }

    protected function tearDown(): void
    {
        foreach ($this->envBackup as $key => $value) {
            if ($value === false) {
                putenv($key);
            } else {
                putenv("$key=$value");
            }
        }
    }

    private function setEnv(string $key, string $value): void
    {
        $this->envBackup[$key] = getenv($key);
        putenv("$key=$value");
    }

    private function assertKeyEntropy(string $key, int $minLength): void
    {
        $this->assertGreaterThanOrEqual($minLength, strlen($key));
        
        $chars = count_chars($key, 1);
        $this->assertGreaterThan(10, count($chars), 'Entropy kunci terlalu rendah');
    }

    public function testGenerateKeyPair_Plaintext_Succeeds(): void
    {
        $km = new KeyManager();
        $kp = $km->generateKeyPair('c1', 'k1', null);
        
        $this->assertSame('c1', $kp->clientId);
        $this->assertSame('k1', $kp->keyId);
        $this->assertNull($kp->wrappedKeyB64);
        $this->assertNull($kp->kekId);
        
        // HMAC secret raw is 32 bytes hex string (64 chars)
        $this->assertKeyEntropy($kp->hmacSecret, 64);
        $this->assertKeyEntropy(base64_decode($kp->aeadKeyB64), 32); // AEAD is 32 bytes raw
    }

    public function testGenerateKeyPair_WithKms_WrapsKey(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('libsodium extension required');
        }

        $kekId = 'test-kek-1';
        $kekRaw = random_bytes(32);
        $this->setEnv('SECURE_KEKS', $kekId);
        $this->setEnv('SECURE_KEK_' . $kekId . '_B64', base64_encode($kekRaw));

        $kms = LocalKms::fromEnv();
        $km = new KeyManager($kms);
        
        $kp = $km->generateKeyPair('c2', 'k2', $kekId);
        
        $this->assertNotNull($kp->wrappedKeyB64);
        $this->assertSame($kekId, $kp->kekId);
        
        // Verify we can unwrap it
        $unwrappedAead = $kms->unwrap($kekId, $kp->wrappedKeyB64, [
            'client_id' => 'c2', 
            'key_id' => 'k2',
            'purpose' => 'securepayload-aead-key'
        ]);
        $this->assertKeyEntropy($unwrappedAead, 32);
        $this->assertSame($unwrappedAead, base64_decode($kp->aeadKeyB64));
    }

    public function testGeneratedHmacKey_HasHighEntropy(): void
    {
        $km = new KeyManager();
        $kp = $km->generateKeyPair('c4', 'k4', null);
        $this->assertKeyEntropy($kp->hmacSecret, 64);
        
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $kp->hmacSecret);
    }

    public function testGeneratedAeadKey_HasHighEntropy(): void
    {
        $km = new KeyManager();
        $kp = $km->generateKeyPair('c5', 'k5', null);
        
        $rawAead = base64_decode($kp->aeadKeyB64, true);
        $this->assertNotFalse($rawAead);
        $this->assertKeyEntropy($rawAead, 32);
        $this->assertSame(32, strlen($rawAead));
    }

    public function testToSqlInsert_ProducesCorrectSql(): void
    {
        $km = new KeyManager();
        $kp = $km->generateKeyPair('c6', 'k6', null);
        
        $sql = $kp->toSqlInsert();
        
        $this->assertStringContainsString('INSERT INTO `secure_keys` (client_id, key_id, hmac_secret, aead_key_b64, wrapped_b64, kek_id)', $sql);
        $this->assertStringContainsString("'c6'", $sql);
        $this->assertStringContainsString("'k6'", $sql);
        $this->assertStringContainsString("'" . $kp->hmacSecret . "'", $sql);
        $this->assertStringContainsString("'" . $kp->aeadKeyB64 . "'", $sql);
        $this->assertStringContainsString("NULL, NULL", $sql);
        
        // Execute SQL to verify it is valid SQLite syntax
        $this->pdo->exec($sql);
        
        $stmt = $this->pdo->query("SELECT * FROM secure_keys WHERE client_id = 'c6'");
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $this->assertNotFalse($row);
        $this->assertSame('c6', $row['client_id']);
    }

    public function testToSqlInsert_WithKms_ProducesCorrectSql(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('libsodium extension required');
        }

        $kekId = 'test-kek-1';
        $kekRaw = random_bytes(32);
        $this->setEnv('SECURE_KEKS', $kekId);
        $this->setEnv('SECURE_KEK_' . $kekId . '_B64', base64_encode($kekRaw));

        $kms = LocalKms::fromEnv();
        $km = new KeyManager($kms);
        
        $kp = $km->generateKeyPair('c7', 'k7', $kekId);
        
        $sql = $kp->toSqlInsert('custom_table');
        
        $this->assertStringContainsString('INSERT INTO `custom_table`', $sql);
        // AEAD Plaintext should be NULL
        $this->assertStringContainsString("'" . $kp->hmacSecret . "', NULL, '" . $kp->wrappedKeyB64 . "', '" . $kekId . "'", $sql);
    }

    public function testToSqlInsert_RejectsMaliciousTableName(): void
    {
        $km = new KeyManager();
        $kp = $km->generateKeyPair('c9', 'k9', null);

        $this->expectException(\InvalidArgumentException::class);
        $kp->toSqlInsert('secure_keys`; DROP TABLE users; --');
    }

    public function testToArray_ContainsAllExpectedFields(): void
    {
        $km = new KeyManager();
        $kp = $km->generateKeyPair('c8', 'k8', null);
        
        $array = $kp->toArray();
        
        $this->assertArrayHasKey('client_id', $array);
        $this->assertArrayHasKey('key_id', $array);
        $this->assertArrayHasKey('hmac_secret', $array);
        $this->assertArrayHasKey('aead_key_b64', $array);
        $this->assertArrayHasKey('wrapped_b64', $array);
        $this->assertArrayHasKey('kek_id', $array);
        
        $this->assertSame('c8', $array['client_id']);
        $this->assertSame('k8', $array['key_id']);
        $this->assertSame($kp->hmacSecret, $array['hmac_secret']);
        $this->assertSame($kp->aeadKeyB64, $array['aead_key_b64']);
    }

    // [COV-KM-01] Constructor tanpa KMS (plaintext mode)
    public function testConstructor_WithoutKms_GeneratesPlaintextKeys(): void
    {
        $manager = new KeyManager(); // null KMS
        $result  = $manager->generateKeyPair('plain-client', 'plain-key');

        $this->assertNull($result->wrappedKeyB64,
            'Tanpa KMS, wrapped key harus null'
        );
        $this->assertNotEmpty($result->aeadKeyB64,
            'AEAD key plaintext harus ada'
        );
        $this->assertNotEmpty($result->hmacSecret);
    }

    // [COV-KM-02] generateKeyPair dengan KMS tapi kekId null → throw
    public function testGenerateKeyPair_WithKmsButNullKekId_ThrowsRuntimeException(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium required');
        }
        // Setup LocalKms
        $kekId  = 'test-kek';
        $kekRaw = random_bytes(32);
        $this->setEnv('SECURE_KEKS', $kekId);
        $this->setEnv("SECURE_KEK_{$kekId}_B64", base64_encode($kekRaw));

        $kms     = LocalKms::fromEnv();
        $manager = new KeyManager($kms);

        $this->expectException(\RuntimeException::class);
        $manager->generateKeyPair('client', 'key', null); // kekId null dengan KMS aktif
    }

    // [COV-KM-03] generateEd25519KeyPair menghasilkan kunci valid yang bisa dipakai sodium
    public function testGenerateEd25519KeyPair_ProducesValidUsableKeys(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium required');
        }
        $km = new KeyManager();
        $kp = $km->generateEd25519KeyPair();

        $this->assertArrayHasKey('publicB64', $kp);
        $this->assertArrayHasKey('secretB64', $kp);

        $pub = base64_decode($kp['publicB64'], true);
        $sec = base64_decode($kp['secretB64'], true);
        $this->assertSame(SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, strlen($pub));
        $this->assertSame(SODIUM_CRYPTO_SIGN_SECRETKEYBYTES, strlen($sec));

        // Bukti pasangan kunci benar-benar cocok: sign lalu verify.
        $msg = 'pesan-uji';
        $sig = sodium_crypto_sign_detached($msg, $sec);
        $this->assertTrue(sodium_crypto_sign_verify_detached($sig, $msg, $pub));
    }
}

