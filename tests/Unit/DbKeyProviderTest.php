<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\KMS\DbKeyProvider;
use PDO;
use InvalidArgumentException;
use SecurePayload\KMS\LocalKms;
use RuntimeException;

final class DbKeyProviderTest extends TestCase
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

    private function insertKey(array $data): void
    {
        $stmt = $this->pdo->prepare("
            INSERT INTO secure_keys (client_id, key_id, hmac_secret, aead_key_b64, wrapped_b64, kek_id)
            VALUES (:cid, :kid, :hmac, :aead, :wrap, :kek)
        ");
        $stmt->execute([
            ':cid' => $data['client_id'],
            ':kid' => $data['key_id'],
            ':hmac' => $data['hmac_secret'] ?? null,
            ':aead' => $data['aead_key_b64'] ?? null,
            ':wrap' => $data['wrapped_b64'] ?? null,
            ':kek'  => $data['kek_id'] ?? null
        ]);
    }

    public function testLoad_PlaintextKey_ReturnsCorrectKeys(): void
    {
        $this->insertKey([
            'client_id' => 'c1',
            'key_id' => 'k1',
            'hmac_secret' => 'plain-hmac-secret-123'
        ]);

        $provider = new DbKeyProvider($this->pdo);
        $keys = $provider->load('c1', 'k1');

        $this->assertSame('plain-hmac-secret-123', $keys['hmacSecret']);
        $this->assertNull($keys['aeadKeyB64']);
    }

    public function testLoad_BothKeys_ReturnsCorrectKeys(): void
    {
        $this->insertKey([
            'client_id' => 'c2',
            'key_id' => 'k2',
            'hmac_secret' => 'hmac-2',
            'aead_key_b64' => 'aead-2'
        ]);

        $provider = new DbKeyProvider($this->pdo);
        $keys = $provider->load('c2', 'k2');

        $this->assertSame('hmac-2', $keys['hmacSecret']);
        $this->assertSame('aead-2', $keys['aeadKeyB64']);
    }

    public function testLoad_KeyNotFound_ReturnsNulls(): void
    {
        $provider = new DbKeyProvider($this->pdo);
        $keys = $provider->load('missing', 'missing');

        $this->assertNull($keys['hmacSecret']);
        $this->assertNull($keys['aeadKeyB64']);
    }

    public function testLoad_WrappedKey_WithKms_ReturnsUnwrapped(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('libsodium extension required');
        }

        $kekId = 'test-kek-1';
        $kekRaw = random_bytes(32);
        $this->setEnv('SECURE_KEKS', $kekId);
        $this->setEnv('SECURE_KEK_' . $kekId . '_B64', base64_encode($kekRaw));

        $kms = LocalKms::fromEnv();
        
        $plainAead = random_bytes(32);
        $wrappedAead = $kms->wrap($kekId, $plainAead, ['client_id' => 'c4', 'key_id' => 'k4', 'purpose' => 'securepayload-aead-key']);

        $this->insertKey([
            'client_id' => 'c4',
            'key_id' => 'k4',
            'hmac_secret' => 'plain-hmac',
            'aead_key_b64' => null,
            'wrapped_b64' => $wrappedAead,
            'kek_id' => $kekId
        ]);

        $provider = new DbKeyProvider($this->pdo, [], $kms);

        $keys = $provider->load('c4', 'k4');
        $this->assertSame('plain-hmac', $keys['hmacSecret']);
        $this->assertSame(base64_encode($plainAead), $keys['aeadKeyB64']);
    }

    public function testLoad_WrappedKey_WithoutKms_ThrowsException(): void
    {
        $this->insertKey([
            'client_id' => 'c5',
            'key_id' => 'k5',
            'hmac_secret' => 'plain-hmac',
            'aead_key_b64' => null,
            'wrapped_b64' => 'some-wrapped-data',
            'kek_id' => 'some-kek'
        ]);

        // Tidak passing KMS instance
        $provider = new DbKeyProvider($this->pdo);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Data kunci terenkripsi ditemukan, tapi KMS provider belum dikonfigurasi di DbKeyProvider.');
        
        $provider->load('c5', 'k5');
    }

    /**
     * SEC-07 Regression Test
     */
    public function testConstructor_ValidIdentifiers_Succeeds(): void
    {
        $provider = new DbKeyProvider($this->pdo, [
            'table' => 'my_custom_keys',
            'colClient' => 'cid_val',
            'colKey' => 'kid_val',
            'colHmac' => 'hmac_val',
            'colAeadB64' => 'aead_val',
            'colWrapped' => 'is_wrapped_val',
            'colKekId' => 'exp_val'
        ]);
        
        $this->assertInstanceOf(DbKeyProvider::class, $provider);
    }

    /**
     * SEC-07 Regression Test
     */
    public function testConstructor_InvalidTableName_ThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Nama tabel/kolom tidak valid: \'keys; DROP TABLE keys;\'. Hanya huruf, angka, dan underscore yang diizinkan.');
        
        new DbKeyProvider($this->pdo, [
            'table' => 'keys; DROP TABLE keys;'
        ]);
        $provider = new DbKeyProvider($this->pdo, [
            'table' => 'keys; DROP TABLE keys;'
        ]);
        // Trigger validation in load()
        $provider->load('a', 'b');
    }

    /**
     * SEC-07 Regression Test
     */
    public function testConstructor_InvalidColumnName_ThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Nama tabel/kolom tidak valid');
        
        $provider = new DbKeyProvider($this->pdo, [
            'colClient' => 'client id' // space is invalid
        ]);
        $provider->load('a', 'b');
    }

    /**
     * SEC-07 Regression Test
     */
    public function testConstructor_SpecialCharsInColumn_ThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Nama tabel/kolom tidak valid');
        
        $provider = new DbKeyProvider($this->pdo, [
            'colClient' => 'client_id" OR 1=1--'
        ]);
        $provider->load('a', 'b');
    }

    // [COV-DB-01] Constructor dengan semua custom options
    public function testConstructor_WithCustomColumnNames_LoadsCorrectly(): void
    {
        // Buat table dengan nama kolom custom
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->exec("CREATE TABLE my_keys (
            cid TEXT, kid TEXT, hmac TEXT, aead TEXT, wrapped TEXT, kek TEXT
        )");
        $pdo->exec("INSERT INTO my_keys (cid, kid, hmac) VALUES ('c1', 'k1', 'hmac-value-for-test-ok')");

        $provider = new DbKeyProvider($pdo, [
            'table'      => 'my_keys',
            'colClient'  => 'cid',
            'colKey'     => 'kid',
            'colHmac'    => 'hmac',
            'colAeadB64' => 'aead',
            'colWrapped' => 'wrapped',
            'colKekId'   => 'kek',
        ]);

        $result = $provider->load('c1', 'k1');
        $this->assertSame('hmac-value-for-test-ok', $result['hmacSecret']);
    }

    // [COV-DB-02] Wrapped key + KMS tapi unwrap gagal → RuntimeException dari catch block
    public function testLoad_WrappedKeyWithKms_UnwrapFails_ThrowsRuntimeException(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium required');
        }

        // Setup KMS with correct key
        $kekId = 'test-kek-2';
        $kekRaw = random_bytes(32);
        $this->setEnv('SECURE_KEKS', $kekId);
        $this->setEnv('SECURE_KEK_' . $kekId . '_B64', base64_encode($kekRaw));

        $kms = LocalKms::fromEnv();

        // Insert record with FAKE/tampered wrapped data that KMS cannot unwrap
        $this->insertKey([
            'client_id'    => 'c-fail',
            'key_id'       => 'k-fail',
            'hmac_secret'  => 'hmac-ok',
            'aead_key_b64' => null,
            'wrapped_b64'  => base64_encode('this-is-not-a-valid-wrapped-key-data'),
            'kek_id'       => $kekId,
        ]);

        $provider = new DbKeyProvider($this->pdo, [], $kms);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Gagal membuka kunci');
        $provider->load('c-fail', 'k-fail');
    }

    // [COV-DB-03] KMS unwrap berhasil tapi return bukan 32 byte → RuntimeException
    public function testLoad_WrappedKeyWithKms_UnwrapWrongSize_ThrowsRuntimeException(): void
    {
        // Create a mock KMS that returns an invalid-length key
        $mockKms = new class implements \SecurePayload\KMS\Kms {
            public function wrap(string $kekId, string $plaintext, array $aad = []): string
            {
                return base64_encode($plaintext);
            }
            public function unwrap(string $kekId, string $wrappedB64, array $aad = []): string
            {
                return 'only-16-bytes!!'; // 16 bytes, not 32
            }
        };

        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->exec("CREATE TABLE secure_keys (
            client_id TEXT, key_id TEXT, hmac_secret TEXT,
            aead_key_b64 TEXT, wrapped_b64 TEXT, kek_id TEXT
        )");
        $pdo->exec("INSERT INTO secure_keys
            (client_id, key_id, hmac_secret, wrapped_b64, kek_id)
            VALUES ('c-size', 'k-size', 'hmac-ok', 'fakewrapped==', 'fake-kek')");

        $provider = new DbKeyProvider($pdo, [], $mockKms);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Hasil unwrap KMS tidak valid');
        $provider->load('c-size', 'k-size');
    }
}

