<?php
declare(strict_types=1);

namespace SecurePayload\KMS;

use PDO;
use PDOException;

/**
 * DoctorChecks
 * ------------
 * Audit konfigurasi produksi SecurePayload ("doctor"): KEK terdaftar, panjang secret
 * HMAC di env, izin direktori storage, keamanan replayStore multi-server, dan
 * konsistensi retensi arsip vs jadwal destroy kunci.
 *
 * Prinsip:
 * - TIDAK melempar exception untuk kondisi normal — setiap temuan menjadi entri
 *   ['ok'|'warn'|'fail'] dengan detail string; fail-closed hanya dalam arti "laporkan
 *   FAIL untuk env rusak", bukan throw.
 * - Detail TIDAK PERNAH memuat isi secret (hanya nama env / panjang byte).
 * - Parameter $env bersifat injeksi untuk test: array KOSONG berarti scan process env
 *   (getenv) yang difilter prefix `SECURE_`. Process env tidak pernah dimutasi.
 */
final class DoctorChecks
{
    /** Batas jumlah baris yang dilaporkan satu-per-satu pada check retention. */
    private const RETENTION_MAX_ROWS = 5;

    /**
     * Jalankan seluruh check.
     *
     * @param array<string,mixed> $env     Env sintetis (nama => nilai). Kosong = scan
     *                                     process env untuk semua var berprefix `SECURE_`.
     * @param array<string,mixed> $options Opsi check:
     *                                     ['storage_dir'=>string|null,
     *                                      'multi_server'=>bool,
     *                                      'replay_store_hint'=>string (mis. 'redis', 'file'),
     *                                      'pdo'=>PDO|null, 'table'=>string,
     *                                      'retention_days'=>int (default 90),
     *                                      'now'=>int (override waktu, untuk test),
     *                                      'secret_env_prefix'=>string (default 'SECUREPAYLOAD_')]
     *
     * @return list<array{name:string,level:'ok'|'warn'|'fail',detail:string}>
     */
    public function run(array $env = [], array $options = []): array
    {
        if ($env === []) {
            $env = $this->collectProcessEnv();
        }

        $entries = [];
        $entries[] = $this->checkKeks($env);
        foreach ($this->checkHmacSecrets($env, $options) as $e) {
            $entries[] = $e;
        }
        $entries[] = $this->checkStorageDir($options);
        $entries[] = $this->checkReplayStore($options);
        foreach ($this->checkRetentionVsDestroy($options) as $e) {
            $entries[] = $e;
        }
        return $entries;
    }

    /**
     * Kumpulkan var proses berprefix SECURE_ tanpa memutasi apa pun.
     *
     * @return array<string,string>
     */
    private function collectProcessEnv(): array
    {
        $out = [];
        foreach ($_ENV as $name => $value) {
            if (is_string($name) && str_starts_with($name, 'SECURE_')) {
                $out[$name] = is_string($value) ? $value : (string) $value;
            }
        }
        // getenv() menangkap var yang diset di luar $_ENV (mis. SetEnvironmentVariable /
        // export shell). Gabungkan tanpa menimpa nilai $_ENV yang sudah ada.
        foreach (getenv() as $name => $value) {
            if (str_starts_with($name, 'SECURE_') && !isset($out[$name])) {
                $out[$name] = (string) $value;
            }
        }
        return $out;
    }

    /**
     * Check 1: KEK terdaftar via SECURE_KEKS + SECURE_KEK_{id}_B64 harus base64 tepat 32 byte.
     * Dry-parse saja — isi secret tidak dimasukkan ke detail. SEMUA KEK bermasalah
     * dikumpulkan dalam SATU entri fail (pola sama dengan checkHmacSecrets) agar
     * operator melihat seluruh temuan sekaligus, bukan berulang kali.
     *
     * @param array<string,mixed> $env
     */
    private function checkKeks(array $env): array
    {
        $rawList = trim((string) ($env['SECURE_KEKS'] ?? ''));
        $ids = array_values(array_filter(array_map('trim', explode(',', $rawList)), static fn (string $s): bool => $s !== ''));

        if ($ids === []) {
            return ['name' => 'kek', 'level' => 'fail', 'detail' => 'SECURE_KEKS kosong atau tidak di-set — tidak ada KEK terdaftar.'];
        }

        $okCount = 0;
        $bad = [];
        foreach ($ids as $id) {
            $name = 'SECURE_KEK_' . $id . '_B64';
            $b64 = $env[$name] ?? null;
            if (!is_string($b64) || $b64 === '') {
                $bad[] = "$name tidak ditemukan di env (terdaftar di SECURE_KEKS)";
                continue;
            }
            $raw = base64_decode($b64, true);
            if ($raw === false || strlen($raw) !== 32) {
                $len = $raw === false ? -1 : strlen($raw);
                $bad[] = "$name bukan base64 dari tepat 32 byte (panjang terbaca: $len byte)";
                continue;
            }
            $okCount++;
        }

        if ($bad !== []) {
            return ['name' => 'kek', 'level' => 'fail', 'detail' => implode('; ', $bad) . '.'];
        }
        return ['name' => 'kek', 'level' => 'ok', 'detail' => "$okCount KEK terdaftar dan valid (base64 32 byte)."];
    }

    /**
     * Check 2: secret HMAC di env dengan pattern {PREFIX}{CID}_{KID}_HMAC_SECRET.
     * Panjang < 32 karakter dilaporkan FAIL karena SecurePayloadConfig menolak konstruktor
     * dengan secret < 32 karakter (desain: fail keras, bukan sekadar warn).
     *
     * @param array<string,mixed> $env
     *
     * @return list<array{name:string,level:'ok'|'warn'|'fail',detail:string}>
     */
    private function checkHmacSecrets(array $env, array $options): array
    {
        $prefix = (string) ($options['secret_env_prefix'] ?? 'SECUREPAYLOAD_');
        $pattern = '/^' . preg_quote($prefix, '/') . '[A-Za-z0-9_]+_HMAC_SECRET$/';

        $found = 0;
        $bad = [];
        foreach ($env as $name => $value) {
            if (!is_string($name) || !preg_match($pattern, $name)) {
                continue;
            }
            $found++;
            $len = strlen((string) $value);
            if ($len < 32) {
                $bad[] = "$name terlalu pendek ($len < 32 karakter)";
            }
        }

        if ($found === 0) {
            return [['name' => 'hmac_secret_env', 'level' => 'ok', 'detail' => "Tidak ada env HMAC secret dengan prefix '$prefix' (mungkin memakai DB/KMS) — dilewati."]];
        }
        if ($bad !== []) {
            return [['name' => 'hmac_secret_env', 'level' => 'fail', 'detail' => implode('; ', $bad) . '.']];
        }
        return [['name' => 'hmac_secret_env', 'level' => 'ok', 'detail' => "$found secret HMAC tervalidasi (>= 32 karakter)."]];
    }

    /**
     * Check 3: direktori storage — writable dan permission <= 0770.
     *
     * @return array{name:string,level:'ok'|'warn'|'fail',detail:string}
     */
    private function checkStorageDir(array $options): array
    {
        $dir = $options['storage_dir'] ?? null;
        if (!is_string($dir) || $dir === '') {
            return ['name' => 'storage_dir', 'level' => 'ok', 'detail' => 'Dilewati (opsi storage_dir tidak diset).'];
        }
        if (!is_dir($dir)) {
            return ['name' => 'storage_dir', 'level' => 'fail', 'detail' => "Direktori '$dir' tidak ditemukan."];
        }
        if (!is_writable($dir)) {
            return ['name' => 'storage_dir', 'level' => 'fail', 'detail' => "Direktori '$dir' tidak writable."];
        }
        $perms = fileperms($dir) & 0777;
        if ($perms > 0770) {
            return ['name' => 'storage_dir', 'level' => 'warn', 'detail' => sprintf("Direktori '%s' writable tapi permission %o lebih longgar dari rekomendasi 0770.", $dir, $perms)];
        }
        return ['name' => 'storage_dir', 'level' => 'ok', 'detail' => sprintf("Direktori '%s' writable dengan permission %o.", $dir, $perms)];
    }

    /**
     * Check 4: replayStore multi-server (heuristik, WARN bukan FAIL — tidak overclaim).
     *
     * @return array{name:string,level:'ok'|'warn'|'fail',detail:string}
     */
    private function checkReplayStore(array $options): array
    {
        $multiServer = !empty($options['multi_server']);
        if (!$multiServer) {
            return ['name' => 'replay_store', 'level' => 'ok', 'detail' => 'Dilewati (multi_server tidak diaktifkan).'];
        }
        $hint = strtolower((string) ($options['replay_store_hint'] ?? ''));
        if (str_contains($hint, 'redis') || str_contains($hint, 'memcached')) {
            return ['name' => 'replay_store', 'level' => 'ok', 'detail' => "Indikasi replayStore eksternal terdeteksi ('$hint')."];
        }
        return ['name' => 'replay_store', 'level' => 'warn', 'detail' => 'Tidak ada indikasi Redis/Memcached pada hint replayStore — replayStore file-based/in-process tidak aman untuk deployment multi-server.'];
    }

    /**
     * Check 5: retensi arsip vs destroy_after — kunci aktif/retiring yang akan dihancurkan
     * SEBELUM masa retensi arsip berakhir dilaporkan warn (maks RETENTION_MAX_ROWS entri
     * individual, sisanya diagregasi).
     *
     * Tanpa opsi pdo -> dilewati ('ok'). Kolom/tabel lifecycle belum terpasang -> dilewati.
     *
     * @return list<array{name:string,level:'ok'|'warn'|'fail',detail:string}>
     */
    private function checkRetentionVsDestroy(array $options): array
    {
        $pdo = $options['pdo'] ?? null;
        if (!$pdo instanceof PDO) {
            return [['name' => 'retention_vs_destroy', 'level' => 'ok', 'detail' => 'Dilewati (opsi pdo tidak diset).']];
        }

        $table = $this->qIdentifier((string) ($options['table'] ?? 'secure_keys'));
        $retentionDays = (int) ($options['retention_days'] ?? 90);
        $now = isset($options['now']) ? (int) $options['now'] : time();
        $threshold = $now + max(0, $retentionDays) * 86400;

        try {
            $stmt = $pdo->prepare(
                "SELECT client_id, key_id, status, destroy_after FROM $table
                 WHERE (status IN ('active','retiring') OR status IS NULL OR status = '')
                   AND destroy_after IS NOT NULL AND destroy_after < :threshold
                 ORDER BY destroy_after ASC"
            );
            $stmt->execute([':threshold' => $threshold]);
            /** @var list<array<string,mixed>> $rows */
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            // Tabel/kolom lifecycle belum dipasang = fitur destroy nonaktif = tidak ada
            // yang bisa dijadwalkan hancur; bukan kondisi gagal.
            return [['name' => 'retention_vs_destroy', 'level' => 'ok', 'detail' => 'Dilewati (tabel/kolom lifecycle belum terpasang: ' . $e->getMessage() . ').']];
        }

        if ($rows === []) {
            return [['name' => 'retention_vs_destroy', 'level' => 'ok', 'detail' => "Semua kunci aktif/retiring bertahan melebihi ambang retensi $retentionDays hari."]];
        }

        $entries = [];
        $shown = array_slice($rows, 0, self::RETENTION_MAX_ROWS);
        foreach ($shown as $row) {
            $cid = (string) ($row['client_id'] ?? '?');
            $kid = (string) ($row['key_id'] ?? '?');
            $status = ((string) ($row['status'] ?? '')) ?: 'active';
            $destroyAfter = (int) $row['destroy_after'];
            $entries[] = [
                'name' => 'retention_vs_destroy',
                'level' => 'warn',
                'detail' => sprintf(
                    'Kunci %s/%s (status %s) dijadwalkan hancur %s — sebelum masa retensi %d hari berakhir.',
                    $cid,
                    $kid,
                    $status,
                    date('c', $destroyAfter),
                    $retentionDays
                ),
            ];
        }
        $rest = count($rows) - count($shown);
        if ($rest > 0) {
            $entries[] = ['name' => 'retention_vs_destroy', 'level' => 'warn', 'detail' => "Dan $rest baris lainnya dalam kondisi serupa (diagregasi)."];
        }
        return $entries;
    }

    /**
     * Validasi identifier SQL (whitelist regex sama seperti DbKeyProvider).
     *
     * @throws \InvalidArgumentException Jika identifier tidak valid.
     */
    private function qIdentifier(string $id): string
    {
        if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $id)) {
            throw new \InvalidArgumentException(
                "Nama tabel tidak valid: '$id'. Hanya huruf, angka, dan underscore yang diizinkan."
            );
        }
        return $id;
    }
}
