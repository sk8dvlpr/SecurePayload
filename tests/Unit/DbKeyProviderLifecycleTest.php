<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\KMS\DbKeyProvider;
use SecurePayload\KMS\KeyStatus;
use PDO;

final class DbKeyProviderLifecycleTest extends TestCase
{
    private PDO $pdo;
    private int $fixedNow = 1_700_000_000;

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

    private function insertKey(array $data): void
    {
        $stmt = $this->pdo->prepare("
            INSERT INTO secure_keys (client_id, key_id, hmac_secret, aead_key_b64, status, valid_until)
            VALUES (:cid, :kid, :hmac, :aead, :status, :valid_until)
        ");
        $stmt->execute([
            ':cid' => $data['client_id'],
            ':kid' => $data['key_id'],
            ':hmac' => $data['hmac_secret'] ?? null,
            ':aead' => $data['aead_key_b64'] ?? null,
            ':status' => $data['status'] ?? KeyStatus::ACTIVE,
            ':valid_until' => $data['valid_until'] ?? null,
        ]);
    }

    private function provider(): DbKeyProvider
    {
        return new DbKeyProvider($this->pdo, [
            'useKeyLifecycle' => true,
            'clock' => fn (): int => $this->fixedNow,
        ]);
    }

    public function testLoad_ActiveKey_ReturnsSecrets(): void
    {
        $this->insertKey([
            'client_id' => 'c1',
            'key_id' => 'k1',
            'hmac_secret' => 'active-hmac-secret-must-be-32bytes!!',
            'status' => KeyStatus::ACTIVE,
        ]);

        $keys = $this->provider()->load('c1', 'k1');

        $this->assertSame('active-hmac-secret-must-be-32bytes!!', $keys['hmacSecret']);
        $this->assertSame(KeyStatus::ACTIVE, $keys['keyStatus']);
        $this->assertNull($keys['validUntil']);
    }

    public function testLoad_RetiringKeyWithinGrace_ReturnsSecrets(): void
    {
        $this->insertKey([
            'client_id' => 'c1',
            'key_id' => 'k1',
            'hmac_secret' => 'retiring-hmac-secret-must-be-32bytes!',
            'status' => KeyStatus::RETIRING,
            'valid_until' => $this->fixedNow + 3600,
        ]);

        $keys = $this->provider()->load('c1', 'k1');

        $this->assertSame('retiring-hmac-secret-must-be-32bytes!', $keys['hmacSecret']);
        $this->assertSame(KeyStatus::RETIRING, $keys['keyStatus']);
        $this->assertSame($this->fixedNow + 3600, $keys['validUntil']);
    }

    public function testLoad_RetiringKeyExpired_ReturnsNulls(): void
    {
        $this->insertKey([
            'client_id' => 'c1',
            'key_id' => 'k1',
            'hmac_secret' => 'expired-hmac-secret-must-be-32bytes!!',
            'status' => KeyStatus::RETIRING,
            'valid_until' => $this->fixedNow - 1,
        ]);

        $keys = $this->provider()->load('c1', 'k1');

        $this->assertNull($keys['hmacSecret']);
        $this->assertNull($keys['aeadKeyB64']);
    }

    public function testLoad_RevokedKey_ReturnsNulls(): void
    {
        $this->insertKey([
            'client_id' => 'c1',
            'key_id' => 'k1',
            'hmac_secret' => 'revoked-hmac-secret-must-be-32bytes!',
            'status' => KeyStatus::REVOKED,
        ]);

        $keys = $this->provider()->load('c1', 'k1');

        $this->assertNull($keys['hmacSecret']);
    }

    public function testLoad_RetiringAtExactBoundary_IsStillLoadable(): void
    {
        $this->insertKey([
            'client_id' => 'c1',
            'key_id' => 'k1',
            'hmac_secret' => 'boundary-hmac-secret-must-be-32bytes',
            'status' => KeyStatus::RETIRING,
            'valid_until' => $this->fixedNow,
        ]);

        $keys = $this->provider()->load('c1', 'k1');

        $this->assertSame('boundary-hmac-secret-must-be-32bytes', $keys['hmacSecret']);
    }

    public function testLoad_WithoutLifecycleFlag_IgnoresRevokedStatus(): void
    {
        $this->insertKey([
            'client_id' => 'c1',
            'key_id' => 'k1',
            'hmac_secret' => 'legacy-hmac-secret-must-be-32bytes!!',
            'status' => KeyStatus::REVOKED,
        ]);

        $provider = new DbKeyProvider($this->pdo);
        $keys = $provider->load('c1', 'k1');

        $this->assertSame('legacy-hmac-secret-must-be-32bytes!!', $keys['hmacSecret']);
        $this->assertArrayNotHasKey('keyStatus', $keys);
    }

    public function testLoad_KeyNotFound_ReturnsNulls(): void
    {
        $keys = $this->provider()->load('missing', 'missing');

        $this->assertNull($keys['hmacSecret']);
    }
}
