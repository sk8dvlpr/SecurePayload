<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Integration;

use PDO;
use PHPUnit\Framework\TestCase;
use SecurePayload\Exceptions\KeyDestroyedException;
use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\KMS\DbKeyProvider;
use SecurePayload\KMS\KeyLifecycleManager;
use SecurePayload\KMS\KeyStatus;
use SecurePayload\SecurePayload;

/**
 * Round-trip arsip nyata:
 * client (mode both + deriveKeys) -> request terenkripsi -> diarsipkan (headers+rawBody+
 * method/path/query) -> rotasi kunci -> decryptArchivedLog tetap membaca kunci TERCATAT
 * di baris arsip (bukan kunci aktif), lalu gate lifecycle destroyed/deleted.
 */
final class ArchiveDecryptRoundTripTest extends TestCase
{
    private PDO $pdo;
    private int $fixedNow = 1_700_000_000;

    private const CID = 'partner1';
    private const KID_V1 = 'key_v1';
    private const KID_V2 = 'key_v2';
    private const PAYLOAD = ['amount' => 1250, 'note' => 'arsip-debug', 'items' => ['a', 'b']];

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->exec('
            CREATE TABLE secure_keys (
                client_id VARCHAR(50),
                key_id VARCHAR(50),
                hmac_secret VARCHAR(255),
                aead_key_b64 VARCHAR(255),
                wrapped_b64 TEXT,
                kek_id VARCHAR(50),
                status VARCHAR(20) NOT NULL DEFAULT \'active\',
                valid_until INTEGER NULL,
                destroy_after INTEGER NULL,
                PRIMARY KEY(client_id, key_id)
            )
        ');
    }

    // ---------------------------------------------------------------- helpers

    private function insertKeyRow(string $kid, string $hmac, string $aeadB64, string $status = KeyStatus::ACTIVE): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO secure_keys (client_id, key_id, hmac_secret, aead_key_b64, status) VALUES (?, ?, ?, ?, ?)'
        );
        $stmt->execute([self::CID, $kid, $hmac, $aeadB64, $status]);
    }

    /**
     * Server memuat kunci dari DB (pola production), bukan dari konfigurasi statis.
     */
    private function newServer(): SecurePayload
    {
        $provider = new DbKeyProvider($this->pdo, [
            'useKeyLifecycle' => true,
            'clock' => fn (): int => $this->fixedNow,
        ]);
        return new SecurePayload([
            'mode' => 'both',
            'deriveKeys' => true,
            'keyLoader' => fn (string $cid, string $kid): array => $provider->load($cid, $kid),
        ]);
    }

    private function newClient(string $kid, string $hmac, string $aeadB64): SecurePayload
    {
        return new SecurePayload([
            'mode' => 'both',
            'deriveKeys' => true,
            'clientId' => self::CID,
            'keyId' => $kid,
            'hmacSecretRaw' => $hmac,
            'aeadKeyB64' => $aeadB64,
        ]);
    }

    /**
     * Manager dengan parameter rekonstruksi yang sama seperti sisi verifikasi asli
     * (deriveKeys=true, versi default) — wajib cocok, kalau tidak dekripsi gagal-closed.
     */
    private function newManager(): KeyLifecycleManager
    {
        return new KeyLifecycleManager($this->pdo, [
            'clock' => fn (): int => $this->fixedNow,
            'deriveKeys' => true,
            'useDestroyAfter' => true,
        ]);
    }

    /**
     * Simulasikan server menerima lalu mengarsipkan request: hasil verify() dipakai untuk
     * merekam konteks kanonik yang dibutuhkan rekonstruksi nonce/AAD saat decrypt arsip.
     *
     * @return array{client_id:string,key_id:string,ciphertext:string,headers:array<string,string>,method:string,path:string,query:mixed}
     */
    private function sendAndArchive(SecurePayload $server, SecurePayload $client, string $url, string $method, string $path, array $query): array
    {
        [$headers, $rawBody] = $client->buildHeadersAndBody($url, $method, self::PAYLOAD);

        // Sanity: round-trip verifikasi asli harus lolos sebelum arsip layak dipercaya.
        $verified = $server->verifyOrThrow($headers, $rawBody, $method, $path, $query);
        $this->assertSame(self::PAYLOAD, json_decode((string) $verified['bodyPlain'], true));

        return [
            'client_id' => self::CID,
            'key_id' => (string) $headers[SecurePayload::HX_KEY_ID],
            'ciphertext' => $rawBody,
            'headers' => $headers,
            'method' => $method,
            'path' => $path,
            'query' => $query,
        ];
    }

    // ------------------------------------------------------------------ tests

    public function testRotatedKey_ArchiveStillDecryptsWithItsRecordedKey(): void
    {
        $oldHmac = 'old-hmac-secret-must-be-32bytes-long!!';
        $oldAead = base64_encode(str_repeat("\x01", 32));
        $this->insertKeyRow(self::KID_V1, $oldHmac, $oldAead);

        $server = $this->newServer();
        $manager = $this->newManager();

        // 1. Request v1 diarsipkan SEBELUM rotasi.
        $archiveV1 = $this->sendAndArchive(
            $server,
            $this->newClient(self::KID_V1, $oldHmac, $oldAead),
            'https://api.test/v1/pay?b=2&a=1',
            'POST',
            '/v1/pay',
            ['b' => '2', 'a' => '1']
        );

        // 2. Rotasi via KeyLifecycleManager: retire kunci lama (grace) + insert kunci baru.
        $manager->retire(self::CID, self::KID_V1, 3600);
        $newHmac = 'new-hmac-secret-must-be-32bytes-long!';
        $newAead = base64_encode(str_repeat("\x02", 32));
        $this->insertKeyRow(self::KID_V2, $newHmac, $newAead);
        $this->assertSame(KeyStatus::RETIRING, $manager->statusOf(self::CID, self::KID_V1));

        // 3. Kunci baru berfungsi normal terhadap server.
        $archiveNewActive = $this->sendAndArchive(
            $this->newServer(),
            $this->newClient(self::KID_V2, $newHmac, $newAead),
            'https://api.test/v2/pay',
            'POST',
            '/v2/pay',
            []
        );

        // 4. Arsip LAMA masih terdekripsi dengan kunci TERCATAT di baris arsip (v1),
        //    meski kunci aktif sekarang v2 dan v1 sudah retiring.
        $plain = $manager->decryptArchivedLog($archiveV1);
        $this->assertSame(self::PAYLOAD, json_decode($plain, true));

        // 5. Arsip baru pun terdekripsi dengan kuncinya sendiri (v2).
        $plainNew = $manager->decryptArchivedLog($archiveNewActive);
        $this->assertSame(self::PAYLOAD, json_decode($plainNew, true));
    }

    public function testRevokedRecordedKey_ArchiveDecryptRejected(): void
    {
        $hmac = 'revoked-hmac-secret-must-be-32bytes!!';
        $aead = base64_encode(str_repeat("\x03", 32));
        $this->insertKeyRow(self::KID_V1, $hmac, $aead);

        $archive = $this->sendAndArchive(
            $this->newServer(),
            $this->newClient(self::KID_V1, $hmac, $aead),
            'https://api.test/v1/x',
            'POST',
            '/v1/x',
            []
        );

        $this->newManager()->revoke(self::CID, self::KID_V1);

        try {
            $this->newManager()->decryptArchivedLog($archive);
            $this->fail('Arsip atas kunci revoked harus ditolak');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::UNAUTHORIZED, $e->getCode());
        }
    }

    public function testDestroyedRecordedKey_ArchiveThrowsStandaloneException(): void
    {
        $hmac = 'destroy-hmac-secret-must-be-32bytes!!';
        $aead = base64_encode(str_repeat("\x04", 32));
        $this->insertKeyRow(self::KID_V1, $hmac, $aead);

        $archive = $this->sendAndArchive(
            $this->newServer(),
            $this->newClient(self::KID_V1, $hmac, $aead),
            'https://api.test/v1/y',
            'POST',
            '/v1/y',
            []
        );

        $manager = $this->newManager();
        // Seluruh rantai destroy end-to-end: jadwal -> due -> eksekusi.
        $manager->scheduleDestroy(self::CID, self::KID_V1, $this->fixedNow + 60);
        $this->assertFalse($manager->destroyIfDue(self::CID, self::KID_V1));

        $this->fixedNow += 61;
        $this->assertTrue($manager->destroyIfDue(self::CID, self::KID_V1));

        try {
            $manager->decryptArchivedLog($archive);
            $this->fail('Arsip atas kunci destroyed harus melempar KeyDestroyedException');
        } catch (KeyDestroyedException $e) {
            $this->assertSame(['client_id' => self::CID, 'key_id' => self::KID_V1], $e->getContext());
        }
    }

    public function testDeletedRecordedKey_ArchiveDecryptRejected(): void
    {
        $hmac = 'deleted-hmac-secret-must-be-32bytes!!';
        $aead = base64_encode(str_repeat("\x05", 32));
        $this->insertKeyRow(self::KID_V1, $hmac, $aead);

        $archive = $this->sendAndArchive(
            $this->newServer(),
            $this->newClient(self::KID_V1, $hmac, $aead),
            'https://api.test/v1/z?q=x',
            'GET',
            '/v1/z',
            ['q' => 'x']
        );

        $stmt = $this->pdo->prepare('DELETE FROM secure_keys WHERE client_id = ? AND key_id = ?');
        $stmt->execute([self::CID, self::KID_V1]);

        try {
            $this->newManager()->decryptArchivedLog($archive);
            $this->fail('Baris kunci hilang harus ditolak');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::BAD_REQUEST, $e->getCode());
        }
    }
}
