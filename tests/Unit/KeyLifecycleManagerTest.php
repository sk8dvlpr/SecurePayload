<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PDO;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SecurePayload\Exceptions\KeyDestroyedException;
use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\KMS\KeyLifecycleManager;
use SecurePayload\KMS\KeyStatus;
use SecurePayload\SecurePayload;

final class KeyLifecycleManagerTest extends TestCase
{
    private PDO $pdo;
    private int $fixedNow = 1_700_000_000;

    private const CID = 'client_a';
    private const KID = 'key_v1';
    private const HMAC = 'unit-hmac-secret-must-be-32bytes!!';
    private const AEAD_B64 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='; // 32 byte 0x00

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

    private function manager(array $opts = [], ?\SecurePayload\KMS\Kms $kms = null): KeyLifecycleManager
    {
        return new KeyLifecycleManager($this->pdo, $opts + [
            'clock' => fn (): int => $this->fixedNow,
        ], $kms);
    }

    private function insertKey(array $data): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO secure_keys (client_id, key_id, hmac_secret, aead_key_b64, wrapped_b64, kek_id, status, valid_until, destroy_after)
             VALUES (:cid, :kid, :hmac, :aead, :wrapped, :kek, :status, :valid_until, :destroy_after)'
        );
        $stmt->execute([
            ':cid' => $data['client_id'] ?? self::CID,
            ':kid' => $data['key_id'] ?? self::KID,
            // array_key_exists (bukan ??): null eksplisit harus tetap tersimpan sebagai
            // NULL di DB, bukan jatuh ke nilai default.
            ':hmac' => array_key_exists('hmac_secret', $data) ? $data['hmac_secret'] : self::HMAC,
            ':aead' => array_key_exists('aead_key_b64', $data) ? $data['aead_key_b64'] : self::AEAD_B64,
            ':wrapped' => $data['wrapped_b64'] ?? null,
            ':kek' => $data['kek_id'] ?? null,
            ':status' => $data['status'] ?? KeyStatus::ACTIVE,
            ':valid_until' => $data['valid_until'] ?? null,
            ':destroy_after' => $data['destroy_after'] ?? null,
        ]);
    }

    private function fetchRow(string $kid = self::KID): array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM secure_keys WHERE client_id = :cid AND key_id = :kid');
        $stmt->execute([':cid' => self::CID, ':kid' => $kid]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $this->assertIsArray($row, 'Baris kunci harus ada di DB');
        return $row;
    }

    /**
     * Bangun arsip nyata lewat facade (mode aead): headers + encrypted body.
     *
     * @return array{headers:array<string,string>, body:string}
     */
    private function buildEncryptedRequest(string $aeadB64, string $url = 'https://api.test/v1/orders'): array
    {
        $client = new SecurePayload([
            'mode' => 'aead',
            'clientId' => self::CID,
            'keyId' => self::KID,
            'aeadKeyB64' => $aeadB64,
        ]);
        /** @var array{0:array<string,string>,1:string} $built */
        $built = $client->buildHeadersAndBody($url, 'POST', ['amount' => 42, 'note' => 'arsip']);
        return ['headers' => $built[0], 'body' => $built[1]];
    }

    private function makeArchive(array $req, array $overrides = []): array
    {
        return $overrides + [
            'client_id' => self::CID,
            'key_id' => self::KID,
            'ciphertext' => $req['body'],
            'headers' => $req['headers'],
            'method' => 'POST',
            'path' => '/v1/orders',
            'query' => [],
        ];
    }

    // --------------------------------------------------------------- statusOf

    public function testStatusOf_ActiveKey_ReturnsActive(): void
    {
        $this->insertKey([]);
        $this->assertSame(KeyStatus::ACTIVE, $this->manager()->statusOf(self::CID, self::KID));
    }

    public function testStatusOf_MissingKey_ThrowsBadRequest(): void
    {
        try {
            $this->manager()->statusOf('ghost', 'ghost');
            $this->fail('Harus melempar SecurePayloadException');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::BAD_REQUEST, $e->getCode());
        }
    }

    // ------------------------------------------------------------------ retire

    public function testRetire_SetsRetiringAndValidUntilWithInjectedClock(): void
    {
        $this->insertKey([]);
        $this->manager()->retire(self::CID, self::KID, 3600);

        $this->assertSame(KeyStatus::RETIRING, $this->manager()->statusOf(self::CID, self::KID));
        $row = $this->fetchRow();
        $this->assertSame($this->fixedNow + 3600, (int) $row['valid_until']);
    }

    public function testRetire_MissingKey_ThrowsBadRequest(): void
    {
        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionCode(SecurePayloadException::BAD_REQUEST);
        $this->manager()->retire('ghost', 'ghost', 60);
    }

    public function testRetire_DestroyedKey_IsRefusedFailClosed(): void
    {
        $this->insertKey(['status' => KeyStatus::DESTROYED]);
        try {
            $this->manager()->retire(self::CID, self::KID, 60);
            $this->fail('Transisi keluar dari destroyed harus ditolak');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::UNPROCESSABLE, $e->getCode());
        }
        $this->assertSame(KeyStatus::DESTROYED, $this->fetchRow()['status']);
    }

    public function testRetire_RevokedKey_IsRefused_NoResurrection(): void
    {
        // revoked -> retiring akan menyetel valid_until masa depan = menghidupkan kembali
        // akses lewat grace window. Harus ditolak.
        $this->insertKey(['status' => KeyStatus::REVOKED]);
        try {
            $this->manager()->retire(self::CID, self::KID, 60);
            $this->fail('Transisi revoked -> retiring harus ditolak');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::UNPROCESSABLE, $e->getCode());
        }
        $this->assertSame(KeyStatus::REVOKED, $this->fetchRow()['status']);
    }

    // ------------------------------------------------------------------ revoke

    public function testRevoke_SetsRevokedStatus(): void
    {
        $this->insertKey(['status' => KeyStatus::RETIRING, 'valid_until' => $this->fixedNow + 100]);
        $this->manager()->revoke(self::CID, self::KID);

        $this->assertSame(KeyStatus::REVOKED, $this->manager()->statusOf(self::CID, self::KID));
        $this->assertNull($this->fetchRow()['valid_until']);
    }

    public function testRevoke_MissingKey_ThrowsBadRequest(): void
    {
        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionCode(SecurePayloadException::BAD_REQUEST);
        $this->manager()->revoke('ghost', 'ghost');
    }

    // --------------------------------------------------------- scheduleDestroy

    public function testScheduleDestroy_WritesColumnWithoutChangingStatus(): void
    {
        $this->insertKey([]);
        $this->manager(['useDestroyAfter' => true])
            ->scheduleDestroy(self::CID, self::KID, $this->fixedNow + 86400);

        $row = $this->fetchRow();
        $this->assertSame($this->fixedNow + 86400, (int) $row['destroy_after']);
        $this->assertSame(KeyStatus::ACTIVE, $row['status']);
    }

    public function testScheduleDestroy_FeatureDisabled_ThrowsRuntime(): void
    {
        $this->insertKey([]);
        $this->expectException(RuntimeException::class);
        $this->manager()->scheduleDestroy(self::CID, self::KID, $this->fixedNow + 86400);
    }

    // ------------------------------------------------------------ destroyIfDue

    public function testDestroyIfDue_NotYetDue_ReturnsFalseAndKeepsActive(): void
    {
        $this->insertKey(['destroy_after' => $this->fixedNow + 100]);
        $mgr = $this->manager(['useDestroyAfter' => true]);

        $this->assertFalse($mgr->destroyIfDue(self::CID, self::KID));
        $this->assertSame(KeyStatus::ACTIVE, $this->fetchRow()['status']);
    }

    public function testDestroyIfDue_DueAfterClockAdvances_ReturnsTrueAndDestroys(): void
    {
        $this->insertKey(['destroy_after' => $this->fixedNow + 100]);
        $mgr = $this->manager(['useDestroyAfter' => true]);

        $this->fixedNow += 101; // clock maju melewati jadwal
        $this->assertTrue($mgr->destroyIfDue(self::CID, self::KID));
        $this->assertSame(KeyStatus::DESTROYED, $this->fetchRow()['status']);

        // Panggilan kedua: sudah destroyed -> false (tidak ada eksekusi baru).
        $this->assertFalse($mgr->destroyIfDue(self::CID, self::KID));
    }

    public function testDestroyIfDue_NullSchedule_ReturnsFalse(): void
    {
        $this->insertKey([]);
        $this->assertFalse($this->manager(['useDestroyAfter' => true])->destroyIfDue(self::CID, self::KID));
    }

    public function testDestroyIfDue_MissingRow_ReturnsFalse(): void
    {
        $this->assertFalse($this->manager(['useDestroyAfter' => true])->destroyIfDue('ghost', 'ghost'));
    }

    public function testDestroyIfDue_StatusKosongSkemaLama_TetapDieksekusi(): void
    {
        // Skema lama boleh memiliki status kosong (''/NULL): kondisi atomik
        // wajib menanganinya sebagai non-destroyed sehingga destroy tetap jalan.
        $this->insertKey(['destroy_after' => $this->fixedNow - 1]);
        $stmt = $this->pdo->prepare(
            'UPDATE secure_keys SET status = :s WHERE client_id = :cid AND key_id = :kid'
        );
        $stmt->execute([':s' => '', ':cid' => self::CID, ':kid' => self::KID]);

        $this->assertTrue($this->manager(['useDestroyAfter' => true])->destroyIfDue(self::CID, self::KID));
        $this->assertSame(KeyStatus::DESTROYED, $this->fetchRow()['status']);

        // Eksekusi ulang oleh worker lain -> false (sudah destroyed).
        $this->assertFalse($this->manager(['useDestroyAfter' => true])->destroyIfDue(self::CID, self::KID));
    }

    // ------------------------------------------------------- decryptArchivedLog

    public function testDecryptArchivedLog_HappyPath_ReturnsOriginalPlaintext(): void
    {
        $aeadB64 = base64_encode(random_bytes(32));
        $req = $this->buildEncryptedRequest($aeadB64);
        $this->insertKey(['aead_key_b64' => $aeadB64]);

        $plain = $this->manager()->decryptArchivedLog($this->makeArchive($req));

        $this->assertSame(['amount' => 42, 'note' => 'arsip'], json_decode($plain, true));
    }

    public function testDecryptArchivedLog_TamperedContext_FailsClosedUnauthorized(): void
    {
        $aeadB64 = base64_encode(random_bytes(32));
        $req = $this->buildEncryptedRequest($aeadB64);
        $this->insertKey(['aead_key_b64' => $aeadB64]);

        // method/path arsip dimanipulasi -> nonce rekonstruksi berubah -> dekripsi gagal.
        $archive = $this->makeArchive($req, ['path' => '/v1/tampered']);
        try {
            $this->manager()->decryptArchivedLog($archive);
            $this->fail('Dekripsi dengan konteks yang dimanipulasi harus gagal');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::UNAUTHORIZED, $e->getCode());
        }
    }

    public function testDecryptArchivedLog_Destroyed_ThrowsStandaloneKeyDestroyed(): void
    {
        $aeadB64 = base64_encode(random_bytes(32));
        $req = $this->buildEncryptedRequest($aeadB64);
        $this->insertKey(['aead_key_b64' => $aeadB64, 'status' => KeyStatus::DESTROYED]);

        try {
            $this->manager()->decryptArchivedLog($this->makeArchive($req));
            $this->fail('Harus melempar KeyDestroyedException');
        } catch (KeyDestroyedException $e) {
            // Tangkap TERPISAH dari SecurePayloadException (kelas standalone).
            $this->assertSame(410, $e->getCode());
            $this->assertSame(['client_id' => self::CID, 'key_id' => self::KID], $e->getContext());
        }
    }

    public function testDecryptArchivedLog_Revoked_ThrowsUnauthorized(): void
    {
        $aeadB64 = base64_encode(random_bytes(32));
        $req = $this->buildEncryptedRequest($aeadB64);
        $this->insertKey(['aead_key_b64' => $aeadB64, 'status' => KeyStatus::REVOKED]);

        try {
            $this->manager()->decryptArchivedLog($this->makeArchive($req));
            $this->fail('Harus melempar SecurePayloadException');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::UNAUTHORIZED, $e->getCode());
        }
    }

    public function testDecryptArchivedLog_RetiringExpiredGrace_ThrowsUnauthorized(): void
    {
        $aeadB64 = base64_encode(random_bytes(32));
        $req = $this->buildEncryptedRequest($aeadB64);
        $this->insertKey([
            'aead_key_b64' => $aeadB64,
            'status' => KeyStatus::RETIRING,
            'valid_until' => $this->fixedNow - 1,
        ]);

        try {
            $this->manager()->decryptArchivedLog($this->makeArchive($req));
            $this->fail('Grace habis harus ditolak');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::UNAUTHORIZED, $e->getCode());
        }
    }

    public function testDecryptArchivedLog_UnknownStatus_FailsClosedUnauthorized(): void
    {
        // Whitelist ketat selaras DbKeyProvider::isKeyLoadable: status tak dikenal
        // (mis. typo 'destroyd') TIDAK BOLEH lolos gate dekripsi.
        $aeadB64 = base64_encode(random_bytes(32));
        $req = $this->buildEncryptedRequest($aeadB64);
        $this->insertKey(['aead_key_b64' => $aeadB64, 'status' => 'destroyd']);

        try {
            $this->manager()->decryptArchivedLog($this->makeArchive($req));
            $this->fail('Status tak dikenal harus ditolak fail-closed');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::UNAUTHORIZED, $e->getCode());
        }
    }

    public function testDecryptArchivedLog_MissingRow_ThrowsBadRequest(): void
    {
        $aeadB64 = base64_encode(random_bytes(32));
        $req = $this->buildEncryptedRequest($aeadB64);

        try {
            $this->manager()->decryptArchivedLog($this->makeArchive($req));
            $this->fail('Baris hilang harus ditolak');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::BAD_REQUEST, $e->getCode());
        }
    }

    public function testDecryptArchivedLog_HmacOnlyRow_ThrowsBadRequest(): void
    {
        $req = $this->buildEncryptedRequest(base64_encode(random_bytes(32)));
        $this->insertKey(['hmac_secret' => self::HMAC, 'aead_key_b64' => null]);

        try {
            $this->manager()->decryptArchivedLog($this->makeArchive($req));
            $this->fail('Arsip mode hmac tidak dapat didekripsi');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::BAD_REQUEST, $e->getCode());
            $this->assertStringContainsString('HMAC', $e->getMessage());
        }
    }

    public function testDecryptArchivedLog_WrappedKey_UnwrapsViaInjectedKms(): void
    {
        $aeadRaw = random_bytes(32);
        $kekRaw = random_bytes(32);
        $kms = $this->makeFakeKms($kekRaw);

        $req = $this->buildEncryptedRequest(base64_encode($aeadRaw));
        $this->insertKey([
            'aead_key_b64' => null,
            'wrapped_b64' => $kms['wrap'](self::CID, self::KID, $aeadRaw),
            'kek_id' => 'kek1',
        ]);

        $plain = $this->manager([], $kms['instance'])->decryptArchivedLog($this->makeArchive($req));
        $this->assertSame(['amount' => 42, 'note' => 'arsip'], json_decode($plain, true));
    }

    public function testDecryptArchivedLog_WrappedKeyWithoutKms_ThrowsRuntime(): void
    {
        $aeadRaw = random_bytes(32);
        $kekRaw = random_bytes(32);
        $kms = $this->makeFakeKms($kekRaw);

        $req = $this->buildEncryptedRequest(base64_encode($aeadRaw));
        $this->insertKey([
            'aead_key_b64' => null,
            'wrapped_b64' => $kms['wrap'](self::CID, self::KID, $aeadRaw),
            'kek_id' => 'kek1',
        ]);

        $this->expectException(RuntimeException::class);
        $this->manager()->decryptArchivedLog($this->makeArchive($req));
    }

    /**
     * Fake KMS berbasis sodium untuk test: AAD context di-ksort + json_encode persis
     * pola LocalKms sehingga context yang salah akan gagal unwrap.
     *
     * @return array{instance:\SecurePayload\KMS\Kms, wrap:(callable(string,string,string):string)}
     */
    private function makeFakeKms(string $kekRaw): array
    {
        $kms = new class($kekRaw) implements \SecurePayload\KMS\Kms {
            public function __construct(private string $kek)
            {
            }

            private function aadStr(array $aad): string
            {
                ksort($aad);
                return (string) json_encode($aad, JSON_UNESCAPED_SLASHES);
            }

            public function wrap(string $kekId, string $plaintext, array $aad): string
            {
                $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
                $ct = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                    $plaintext,
                    $this->aadStr($aad),
                    $nonce,
                    $this->kek
                );
                if ($ct === false) {
                    throw new RuntimeException('fake kms wrap gagal');
                }
                return base64_encode($nonce . $ct);
            }

            public function unwrap(string $kekId, string $blobB64, array $aad): string
            {
                $raw = base64_decode($blobB64, true);
                if (!is_string($raw) || strlen($raw) < 24) {
                    throw new RuntimeException('fake kms blob rusak');
                }
                $pt = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                    substr($raw, 24),
                    $this->aadStr($aad),
                    substr($raw, 0, 24),
                    $this->kek
                );
                if ($pt === false) {
                    throw new RuntimeException('fake kms unwrap gagal (AAD/key salah)');
                }
                return $pt;
            }
        };

        return [
            'instance' => $kms,
            'wrap' => fn (string $cid, string $kid, string $raw): string => $kms->wrap('kek1', $raw, [
                'client_id' => $cid,
                'key_id' => $kid,
                'purpose' => 'securepayload-aead-key',
            ]),
        ];
    }

    public function testExceptionContextIsStoredAndReturned(): void
    {
        $e = new KeyDestroyedException('kunci telah dihancurkan', 410, ['keyId' => 'k1']);
        $this->assertSame(['keyId' => 'k1'], $e->getContext());
    }

    public function testExceptionDefaultCodeIs410(): void
    {
        $e = new KeyDestroyedException();
        $this->assertSame(410, $e->getCode());
        $this->assertSame('', $e->getMessage());
        $this->assertSame([], $e->getContext());
    }

    public function testExceptionBukanSubclassSecurePayloadException(): void
    {
        $e = new KeyDestroyedException('destroyed');
        $this->assertFalse($e instanceof SecurePayloadException);
    }

    public function testExceptionTertangkapTerpisahDariSecurePayloadException(): void
    {
        try {
            throw new KeyDestroyedException('kunci dihancurkan', 410, ['clientId' => 'c1']);
        } catch (SecurePayloadException $e) {
            $this->fail('KeyDestroyedException tidak boleh tertangkap oleh catch SecurePayloadException');
        } catch (KeyDestroyedException $e) {
            $this->assertSame('kunci dihancurkan', $e->getMessage());
            $this->assertSame(['clientId' => 'c1'], $e->getContext());
        }
    }
}
