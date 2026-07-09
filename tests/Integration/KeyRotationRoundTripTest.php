<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Integration;

use PHPUnit\Framework\TestCase;
use SecurePayload\KMS\DbKeyProvider;
use SecurePayload\KMS\KeyManager;
use SecurePayload\KMS\KeyStatus;
use SecurePayload\SecurePayload;
use PDO;

/**
 * Round-trip verifikasi request/response selama rotasi kunci dengan grace period.
 */
final class KeyRotationRoundTripTest extends TestCase
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

    private function provider(): DbKeyProvider
    {
        return new DbKeyProvider($this->pdo, [
            'useKeyLifecycle' => true,
            'clock' => fn (): int => $this->fixedNow,
        ]);
    }

    private function seedRotatedKeys(int $graceSeconds): KeyManager
    {
        $oldHmac = 'old-hmac-secret-must-be-32bytes-long!!';
        $oldAead = base64_encode(str_repeat("\x01", 32));

        $stmt = $this->pdo->prepare(
            'INSERT INTO secure_keys (client_id, key_id, hmac_secret, aead_key_b64, status) VALUES (?, ?, ?, ?, ?)'
        );
        $stmt->execute(['partner1', 'key_v1', $oldHmac, $oldAead, KeyStatus::ACTIVE]);

        $km = new KeyManager();
        $rotation = $km->rotateKey('partner1', 'key_v1', 'key_v2', $graceSeconds);

        $this->pdo->exec($rotation->toSqlUpdateRetiring());
        $this->pdo->exec($rotation->toSqlInsertNew());

        // Selaraskan valid_until dengan jam uji (rotateKey memakai time() nyata).
        $stmt = $this->pdo->prepare('UPDATE secure_keys SET valid_until = ? WHERE client_id = ? AND key_id = ?');
        $stmt->execute([$this->fixedNow + $graceSeconds, 'partner1', 'key_v1']);

        return $km;
    }

    public function testOldKeyWorksDuringGrace_NewKeyWorksImmediately(): void
    {
        $this->seedRotatedKeys(3600);

        $oldHmac = 'old-hmac-secret-must-be-32bytes-long!!';
        $oldAead = base64_encode(str_repeat("\x01", 32));

        $newRow = $this->pdo->query("SELECT hmac_secret, aead_key_b64 FROM secure_keys WHERE key_id = 'key_v2'")
            ->fetch(PDO::FETCH_ASSOC);
        $this->assertNotFalse($newRow);

        $provider = $this->provider();
        $keyLoader = fn (string $cid, string $kid): array => $provider->load($cid, $kid);

        $server = new SecurePayload([
            'mode' => 'both',
            'keyLoader' => $keyLoader,
        ]);

        // Client lama masih pakai key_v1 selama grace.
        $clientOld = new SecurePayload([
            'mode' => 'both',
            'clientId' => 'partner1',
            'keyId' => 'key_v1',
            'hmacSecretRaw' => $oldHmac,
            'aeadKeyB64' => $oldAead,
        ]);
        [$reqHeadersOld, $reqBodyOld] = $clientOld->buildHeadersAndBody('https://api/v1/pay', 'POST', ['amount' => 100]);
        $verifyOld = $server->verify($reqHeadersOld, $reqBodyOld, 'POST', '/v1/pay', []);
        $this->assertTrue($verifyOld['ok'], $verifyOld['error'] ?? '');

        [$respHeadersOld, $respBodyOld] = $server->buildResponse($reqHeadersOld, ['status' => 'ok']);
        $respOld = $clientOld->verifyResponse($respHeadersOld, $respBodyOld, $reqHeadersOld[SecurePayload::HX_NONCE]);
        $this->assertTrue($respOld['ok'], $respOld['error'] ?? '');

        // Client baru pakai key_v2.
        $clientNew = new SecurePayload([
            'mode' => 'both',
            'clientId' => 'partner1',
            'keyId' => 'key_v2',
            'hmacSecretRaw' => $newRow['hmac_secret'],
            'aeadKeyB64' => $newRow['aead_key_b64'],
        ]);
        [$reqHeadersNew, $reqBodyNew] = $clientNew->buildHeadersAndBody('https://api/v1/pay', 'POST', ['amount' => 200]);
        $verifyNew = $server->verify($reqHeadersNew, $reqBodyNew, 'POST', '/v1/pay', []);
        $this->assertTrue($verifyNew['ok'], $verifyNew['error'] ?? '');

        [$respHeadersNew, $respBodyNew] = $server->buildResponse($reqHeadersNew, ['status' => 'ok']);
        $respNew = $clientNew->verifyResponse($respHeadersNew, $respBodyNew, $reqHeadersNew[SecurePayload::HX_NONCE]);
        $this->assertTrue($respNew['ok'], $respNew['error'] ?? '');
    }

    public function testOldKeyRejectedAfterGraceExpires(): void
    {
        $this->seedRotatedKeys(3600);

        // Simulasikan waktu lewat grace window.
        $this->fixedNow += 3601;

        $oldHmac = 'old-hmac-secret-must-be-32bytes-long!!';
        $oldAead = base64_encode(str_repeat("\x01", 32));

        $provider = $this->provider();
        $server = new SecurePayload([
            'mode' => 'both',
            'keyLoader' => fn (string $cid, string $kid): array => $provider->load($cid, $kid),
        ]);

        $clientOld = new SecurePayload([
            'mode' => 'both',
            'clientId' => 'partner1',
            'keyId' => 'key_v1',
            'hmacSecretRaw' => $oldHmac,
            'aeadKeyB64' => $oldAead,
        ]);
        [$reqHeaders, $reqBody] = $clientOld->buildHeadersAndBody('https://api/v1/pay', 'POST', ['amount' => 50]);
        $verify = $server->verify($reqHeaders, $reqBody, 'POST', '/v1/pay', []);
        $this->assertFalse($verify['ok']);
    }

    public function testRevokedKeyRejectedImmediately(): void
    {
        $hmac = 'revoke-hmac-secret-must-be-32bytes!!';
        $aead = base64_encode(str_repeat("\x02", 32));
        $stmt = $this->pdo->prepare(
            'INSERT INTO secure_keys (client_id, key_id, hmac_secret, aead_key_b64, status) VALUES (?, ?, ?, ?, ?)'
        );
        $stmt->execute(['partner1', 'key_v1', $hmac, $aead, KeyStatus::REVOKED]);

        $km = new KeyManager();
        $this->pdo->exec($km->revokeKey('partner1', 'key_v1'));

        $provider = $this->provider();
        $server = new SecurePayload([
            'mode' => 'both',
            'keyLoader' => fn (string $cid, string $kid): array => $provider->load($cid, $kid),
        ]);

        $client = new SecurePayload([
            'mode' => 'both',
            'clientId' => 'partner1',
            'keyId' => 'key_v1',
            'hmacSecretRaw' => $hmac,
            'aeadKeyB64' => $aead,
        ]);
        [$reqHeaders, $reqBody] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['x' => 1]);
        $verify = $server->verify($reqHeaders, $reqBody, 'POST', '/v1/x', []);
        $this->assertFalse($verify['ok']);
    }
}
