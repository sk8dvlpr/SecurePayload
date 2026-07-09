<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use SecurePayload\KMS\KeyManager;
use SecurePayload\KMS\KeyStatus;
use PDO;

final class KeyManagerRotationTest extends TestCase
{
    private PDO $pdo;

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
                status VARCHAR(20) NOT NULL DEFAULT 'active',
                valid_until INTEGER NULL,
                PRIMARY KEY(client_id, key_id)
            )
        ");
    }

    public function testRotateKey_GeneratesNewKeyIdAndGraceTimestamp(): void
    {
        $km = new KeyManager();
        $before = time();
        $result = $km->rotateKey('client1', 'key_v1', null, 3600);
        $after = time();

        $this->assertSame('client1', $result->clientId);
        $this->assertSame('key_v1', $result->oldKeyId);
        $this->assertStringStartsWith('key_v1_rot_', $result->newKeyId);
        $this->assertGreaterThanOrEqual($before + 3600, $result->graceEndsAt);
        $this->assertLessThanOrEqual($after + 3600, $result->graceEndsAt);
        $this->assertSame($result->newKeyId, $result->newKey->keyId);
    }

    public function testRotateKey_WithExplicitNewKeyId_UsesProvidedId(): void
    {
        $km = new KeyManager();
        $result = $km->rotateKey('client1', 'key_v1', 'key_v2', 7200);

        $this->assertSame('key_v2', $result->newKeyId);
        $this->assertSame('key_v2', $result->newKey->keyId);
    }

    public function testRotateKey_InvalidGraceSeconds_Throws(): void
    {
        $km = new KeyManager();
        $this->expectException(InvalidArgumentException::class);
        $km->rotateKey('c1', 'k1', 'k2', 0);
    }

    public function testRotateKey_SqlStatements_AreExecutable(): void
    {
        $hmac = str_repeat('a', 64);
        $aead = base64_encode(str_repeat("\x01", 32));
        $stmt = $this->pdo->prepare(
            'INSERT INTO secure_keys (client_id, key_id, hmac_secret, aead_key_b64, status) VALUES (?, ?, ?, ?, ?)'
        );
        $stmt->execute(['client1', 'key_v1', $hmac, $aead, KeyStatus::ACTIVE]);

        $km = new KeyManager();
        $result = $km->rotateKey('client1', 'key_v1', 'key_v2', 3600);

        $this->pdo->exec($result->toSqlUpdateRetiring());
        $this->pdo->exec($result->toSqlInsertNew());

        $old = $this->pdo->query("SELECT status, valid_until FROM secure_keys WHERE key_id = 'key_v1'")->fetch(PDO::FETCH_ASSOC);
        $this->assertSame(KeyStatus::RETIRING, $old['status']);
        $this->assertNotNull($old['valid_until']);

        $new = $this->pdo->query("SELECT status, hmac_secret FROM secure_keys WHERE key_id = 'key_v2'")->fetch(PDO::FETCH_ASSOC);
        $this->assertSame(KeyStatus::ACTIVE, $new['status']);
        $this->assertSame($result->newKey->hmacSecret, $new['hmac_secret']);
    }

    public function testRotateKey_SqlInsertNew_IncludesLifecycleColumns(): void
    {
        $km = new KeyManager();
        $result = $km->rotateKey('c1', 'k1', 'k2', 86400);
        $sql = $result->toSqlInsertNew();

        $this->assertStringContainsString('status', $sql);
        $this->assertStringContainsString("'active'", $sql);
        $this->assertStringContainsString('valid_until', $sql);
        $this->assertStringContainsString('NULL', $sql);
    }

    public function testRotateKey_SqlUpdateRetiring_SetsRetiringStatus(): void
    {
        $km = new KeyManager();
        $result = $km->rotateKey('c1', 'old_k', 'new_k', 1800);
        $sql = $result->toSqlUpdateRetiring();

        $this->assertStringContainsString("status = 'retiring'", $sql);
        $this->assertStringContainsString('valid_until = ' . $result->graceEndsAt, $sql);
        $this->assertStringContainsString("'old_k'", $sql);
    }

    public function testRevokeKey_ProducesCorrectSql(): void
    {
        $km = new KeyManager();
        $sql = $km->revokeKey('client1', 'key_v1');

        $this->assertStringContainsString("status = 'revoked'", $sql);
        $this->assertStringContainsString('valid_until = NULL', $sql);
        $this->assertStringContainsString("'client1'", $sql);
        $this->assertStringContainsString("'key_v1'", $sql);
    }

    public function testPurgeExpiredRetiringKeys_ProducesCorrectSql(): void
    {
        $km = new KeyManager();
        $sql = $km->purgeExpiredRetiringKeys('secure_keys', 1700000000);

        $this->assertStringContainsString("status = 'retiring'", $sql);
        $this->assertStringContainsString('valid_until < 1700000000', $sql);
        $this->assertStringContainsString("status = 'revoked'", $sql);
    }

    public function testRotateKey_WithEd25519_IncludesClientSecretAndDbColumns(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium required');
        }

        $km = new KeyManager();
        $result = $km->rotateKey('c1', 'k1', 'k2', 3600, null, true, true);

        $this->assertNotNull($result->ed25519SecretKeyB64);
        $this->assertNotNull($result->newKey->ed25519PublicB64);
        $this->assertNotNull($result->newKey->ed25519ServerSecretB64);
        $this->assertNotNull($result->newKey->ed25519ServerPublicB64);

        $sql = $result->toSqlInsertNew();
        $this->assertStringContainsString('ed25519_public_b64', $sql);
        $this->assertStringContainsString('ed25519_server_secret_b64', $sql);
        $this->assertStringContainsString('ed25519_server_public_b64', $sql);
    }

    public function testToSqlInsert_WithLifecycle_IncludesStatusColumns(): void
    {
        $km = new KeyManager();
        $kp = $km->generateKeyPair('c1', 'k1');
        $sql = $kp->toSqlInsert('secure_keys', KeyStatus::ACTIVE, true);

        $this->assertStringContainsString('status', $sql);
        $this->assertStringContainsString('valid_until', $sql);
        $this->pdo->exec($sql);

        $row = $this->pdo->query("SELECT status FROM secure_keys WHERE key_id = 'k1'")->fetch(PDO::FETCH_ASSOC);
        $this->assertSame(KeyStatus::ACTIVE, $row['status']);
    }
}
