<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PDO;
use PHPUnit\Framework\TestCase;
use SecurePayload\KMS\DoctorChecks;

/**
 * DoctorChecks dengan env SINTETIS lewat parameter — process env tidak pernah disentuh.
 *
 * Keputusan desain yang diverifikasi di sini:
 * - Secret HMAC env < 32 karakter => FAIL (konsisten dengan SecurePayloadConfig yang
 *   menolak konstruktor secret < 32 karakter), bukan sekadar warn.
 * - Direktori storage: hanya asersi portable (writable => bukan FAIL; tidak ada => FAIL).
 *   Asersi permission bit sengaja tidak dibuat karena fileperms() tidak dapat
 *   diandalkan di Windows.
 */
final class DoctorChecksTest extends TestCase
{
    /** @var list<string> */
    private array $tempDirs = [];

    protected function tearDown(): void
    {
        foreach ($this->tempDirs as $dir) {
            if (is_dir($dir)) {
                @rmdir($dir);
            }
        }
    }

    // ------------------------------------------------------------------ helpers

    private function validKekEnv(): array
    {
        return [
            'SECURE_KEKS' => 'kek1,kek2',
            'SECURE_KEK_kek1_B64' => base64_encode(str_repeat('a', 32)),
            'SECURE_KEK_kek2_B64' => base64_encode(str_repeat('b', 32)),
        ];
    }

    private function findEntry(array $entries, string $name): ?array
    {
        foreach ($entries as $e) {
            if (($e['name'] ?? null) === $name) {
                return $e;
            }
        }
        return null;
    }

    private function makeTempDir(): string
    {
        $dir = sys_get_temp_dir() . '/sp_doctor_' . uniqid('', true);
        $this->assertTrue(mkdir($dir));
        $this->tempDirs[] = $dir;
        return $dir;
    }

    private function pdoWithLifecycleTable(): PDO
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->exec("
            CREATE TABLE secure_keys (
                client_id VARCHAR(50),
                key_id VARCHAR(50),
                status VARCHAR(20) NOT NULL DEFAULT 'active',
                destroy_after INTEGER NULL
            )
        ");
        return $pdo;
    }

    private function insertKeyRow(PDO $pdo, string $cid, string $kid, string $status, ?int $destroyAfter): void
    {
        $stmt = $pdo->prepare('INSERT INTO secure_keys (client_id, key_id, status, destroy_after) VALUES (?, ?, ?, ?)');
        $stmt->execute([$cid, $kid, $status, $destroyAfter]);
    }

    // --------------------------------------------------------------------- KEK

    public function testKeks_CompleteConfig_ReturnsOk(): void
    {
        $entries = (new DoctorChecks())->run($this->validKekEnv());
        $kek = $this->findEntry($entries, 'kek');
        $this->assertNotNull($kek);
        $this->assertSame('ok', $kek['level']);
        $this->assertStringContainsString('2 KEK', $kek['detail']);
    }

    public function testKeks_MissingList_ReturnsFail(): void
    {
        // Env ada (bukan scan proses) tapi tidak berisi var KEK apa pun.
        $env = ['SECUREPAYLOAD_C_K_HMAC_SECRET' => str_repeat('x', 40)];
        $kek = $this->findEntry((new DoctorChecks())->run($env), 'kek');
        $this->assertNotNull($kek);
        $this->assertSame('fail', $kek['level']);
    }

    public function testKeks_MissingVariableForSecondId_ReturnsFail(): void
    {
        $env = [
            'SECURE_KEKS' => 'kek1,kek2',
            'SECURE_KEK_kek1_B64' => base64_encode(str_repeat('a', 32)),
        ];
        $kek = $this->findEntry((new DoctorChecks())->run($env), 'kek');
        $this->assertNotNull($kek);
        $this->assertSame('fail', $kek['level']);
        $this->assertStringContainsString('SECURE_KEK_kek2_B64', $kek['detail']);
    }

    public function testKeks_WrongLength_ReturnsFailWithoutLeakingSecret(): void
    {
        $secret = base64_encode(str_repeat('c', 31)); // 31 byte — salah panjang
        $env = [
            'SECURE_KEKS' => 'kek1',
            'SECURE_KEK_kek1_B64' => $secret,
        ];
        $kek = $this->findEntry((new DoctorChecks())->run($env), 'kek');
        $this->assertNotNull($kek);
        $this->assertSame('fail', $kek['level']);
        // Detail TIDAK boleh memuat isi secret.
        $this->assertStringNotContainsString($secret, $kek['detail']);
    }

    public function testKeks_NotBase64_ReturnsFail(): void
    {
        $env = [
            'SECURE_KEKS' => 'kek1',
            'SECURE_KEK_kek1_B64' => '!!!bukan-base64!!!',
        ];
        $kek = $this->findEntry((new DoctorChecks())->run($env), 'kek');
        $this->assertNotNull($kek);
        $this->assertSame('fail', $kek['level']);
    }

    public function testKeks_BeberapaMasalah_DiagregasiSatuEntri(): void
    {
        // Semua temuan KEK bermasalah harus muncul dalam SATU entri fail —
        // tidak berhenti di temuan pertama (pola sama dengan checkHmacSecrets).
        $secret = base64_encode(str_repeat('c', 31)); // 31 byte — salah panjang
        $env = [
            'SECURE_KEKS' => 'kek1,kek2,kek3',
            'SECURE_KEK_kek1_B64' => base64_encode(str_repeat('a', 32)), // valid
            'SECURE_KEK_kek2_B64' => $secret,                            // salah panjang
            // kek3: variabel env tidak ada sama sekali
        ];
        $entries = (new DoctorChecks())->run($env);

        $kekEntries = array_values(array_filter(
            $entries,
            static fn (array $e): bool => ($e['name'] ?? null) === 'kek'
        ));
        $this->assertCount(1, $kekEntries, 'Semua temuan KEK diagregasi dalam satu entri.');
        $this->assertSame('fail', $kekEntries[0]['level']);
        $detail = (string) ($kekEntries[0]['detail'] ?? '');
        $this->assertStringContainsString('SECURE_KEK_kek2_B64', $detail);
        $this->assertStringContainsString('SECURE_KEK_kek3_B64', $detail);
        // Detail TIDAK boleh memuat isi secret.
        $this->assertStringNotContainsString($secret, $detail);
    }

    // ---------------------------------------------------------- HMAC secret env

    public function testHmacSecret_ShortSecret_ReturnsFailByDesign(): void
    {
        $env = [
            'SECUREPAYLOAD_CLIENTA_K1_HMAC_SECRET' => str_repeat('x', 20),
        ];
        $e = $this->findEntry((new DoctorChecks())->run($env), 'hmac_secret_env');
        $this->assertNotNull($e);
        $this->assertSame('fail', $e['level'], 'Desain: < 32 karakter adalah FAIL karena konstruktor library menolaknya.');
    }

    public function testHmacSecret_LongEnough_ReturnsOk(): void
    {
        $env = [
            'SECUREPAYLOAD_CLIENTA_K1_HMAC_SECRET' => str_repeat('y', 64),
        ];
        $e = $this->findEntry((new DoctorChecks())->run($env), 'hmac_secret_env');
        $this->assertNotNull($e);
        $this->assertSame('ok', $e['level']);
    }

    public function testHmacSecret_NoVarsFound_ReturnsOkSkipped(): void
    {
        $env = ['UNRELATED_VAR' => 'zzz'];
        $e = $this->findEntry((new DoctorChecks())->run($env), 'hmac_secret_env');
        $this->assertNotNull($e);
        $this->assertSame('ok', $e['level']);
        $this->assertStringContainsStringIgnoringCase('dilewati', $e['detail']);
    }

    public function testHmacSecret_CustomPrefix_IsRespected(): void
    {
        $env = ['MYPREFIX_C_K_HMAC_SECRET' => str_repeat('z', 16)];
        $e = $this->findEntry(
            (new DoctorChecks())->run($env, ['secret_env_prefix' => 'MYPREFIX_']),
            'hmac_secret_env'
        );
        $this->assertNotNull($e);
        $this->assertSame('fail', $e['level']);
    }

    // ------------------------------------------------------------- storage dir

    public function testStorageDir_NotSet_ReturnsOkSkipped(): void
    {
        $e = $this->findEntry((new DoctorChecks())->run([]), 'storage_dir');
        $this->assertNotNull($e);
        $this->assertSame('ok', $e['level']);
    }

    public function testStorageDir_NonexistentPath_ReturnsFail(): void
    {
        $e = $this->findEntry((new DoctorChecks())->run([], ['storage_dir' => 'Z:/definitely/not/here']), 'storage_dir');
        $this->assertNotNull($e);
        $this->assertSame('fail', $e['level']);
    }

    public function testStorageDir_WritableExistingDir_IsPortableNonFail(): void
    {
        // Asersi portable: direktori writable yang ADA tidak boleh FAIL.
        // Permission bit TIDAK diasertakan (fileperms() tak reliabel di Windows).
        $e = $this->findEntry((new DoctorChecks())->run([], ['storage_dir' => $this->makeTempDir()]), 'storage_dir');
        $this->assertNotNull($e);
        $this->assertNotSame('fail', $e['level']);
    }

    // ------------------------------------------------------------ replay store

    public function testReplayStore_MultiServerWithoutHint_ReturnsWarn(): void
    {
        $e = $this->findEntry((new DoctorChecks())->run([], ['multi_server' => true]), 'replay_store');
        $this->assertNotNull($e);
        $this->assertSame('warn', $e['level'], 'Heuristik: WARN bukan FAIL — tidak overclaim.');
    }

    public function testReplayStore_MultiServerWithRedisHint_ReturnsOk(): void
    {
        $e = $this->findEntry((new DoctorChecks())->run([], ['multi_server' => true, 'replay_store_hint' => 'redis-cluster']), 'replay_store');
        $this->assertNotNull($e);
        $this->assertSame('ok', $e['level']);
    }

    public function testReplayStore_SingleServer_ReturnsOkSkipped(): void
    {
        $e = $this->findEntry((new DoctorChecks())->run([]), 'replay_store');
        $this->assertNotNull($e);
        $this->assertSame('ok', $e['level']);
    }

    // --------------------------------------------------- retention vs destroy

    public function testRetention_NearDestroySchedule_EmitsWarn(): void
    {
        $now = 1_700_000_000;
        $pdo = $this->pdoWithLifecycleTable();
        $this->insertKeyRow($pdo, 'c1', 'k1', 'active', $now + 10 * 86400);       // < ambang 90 hari -> warn
        $this->insertKeyRow($pdo, 'c2', 'k2', 'retiring', $now + 400 * 86400);     // jauh -> aman

        $entries = (new DoctorChecks())->run([], [
            'pdo' => $pdo,
            'table' => 'secure_keys',
            'retention_days' => 90,
            'now' => $now,
        ]);
        $warns = array_values(array_filter($entries, fn (array $e): bool =>
            ($e['name'] ?? '') === 'retention_vs_destroy' && ($e['level'] ?? '') === 'warn'));

        $this->assertCount(1, $warns);
        $this->assertStringContainsString('c1/k1', (string) $warns[0]['detail']);
        $this->assertStringContainsString('active', (string) $warns[0]['detail']);
    }

    public function testRetention_AllKeysSafe_ReturnsOk(): void
    {
        $now = 1_700_000_000;
        $pdo = $this->pdoWithLifecycleTable();
        $this->insertKeyRow($pdo, 'c1', 'k1', 'active', $now + 500 * 86400);

        $entries = (new DoctorChecks())->run([], [
            'pdo' => $pdo,
            'table' => 'secure_keys',
            'retention_days' => 90,
            'now' => $now,
        ]);
        $e = $this->findEntry($entries, 'retention_vs_destroy');
        $this->assertNotNull($e);
        $this->assertSame('ok', $e['level']);
    }

    public function testRetention_ManyRows_AggregatesRemainder(): void
    {
        $now = 1_700_000_000;
        $pdo = $this->pdoWithLifecycleTable();
        for ($i = 0; $i < 7; $i++) {
            $this->insertKeyRow($pdo, 'c' . $i, 'k' . $i, 'active', $now + 86400);
        }

        $warnEntries = array_values(array_filter(
            (new DoctorChecks())->run([], ['pdo' => $pdo, 'retention_days' => 90, 'now' => $now]),
            fn (array $e): bool => ($e['name'] ?? '') === 'retention_vs_destroy'
        ));

        // 5 entri individual (batas RETENTION_MAX_ROWS) + 1 agregat sisanya.
        $this->assertCount(6, $warnEntries);
        $last = end($warnEntries);
        $this->assertStringContainsString('2 baris lainnya', (string) $last['detail']);
    }

    public function testRetention_WithoutPdo_ReturnsOkSkipped(): void
    {
        $e = $this->findEntry((new DoctorChecks())->run([]), 'retention_vs_destroy');
        $this->assertNotNull($e);
        $this->assertSame('ok', $e['level']);
        $this->assertStringContainsStringIgnoringCase('dilewati', $e['detail']);
    }

    public function testRetention_TableWithoutLifecycleColumns_ReturnsOkSkipped(): void
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->exec('CREATE TABLE secure_keys (client_id VARCHAR(50), key_id VARCHAR(50))');

        $e = $this->findEntry((new DoctorChecks())->run([], ['pdo' => $pdo]), 'retention_vs_destroy');
        $this->assertNotNull($e);
        $this->assertSame('ok', $e['level'], 'Fitur destroy belum terpasang = bukan kondisi gagal.');
    }

    // ----------------------------------------------------------------- bentuk

    public function testRun_AlwaysReturnsWellFormedEntries(): void
    {
        $entries = (new DoctorChecks())->run([]);
        $this->assertNotEmpty($entries);
        foreach ($entries as $e) {
            $this->assertIsArray($e);
            $this->assertArrayHasKey('name', $e);
            $this->assertArrayHasKey('level', $e);
            $this->assertArrayHasKey('detail', $e);
            $this->assertContains($e['level'], ['ok', 'warn', 'fail']);
            $this->assertIsString($e['detail']);
            $this->assertNotSame('', $e['detail']);
        }
    }
}
