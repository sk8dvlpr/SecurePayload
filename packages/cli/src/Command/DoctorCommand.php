<?php
declare(strict_types=1);

namespace SecurePayload\Cli\Command;

use PDO;
use PDOException;
use SecurePayload\KMS\DoctorChecks;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `securepayload doctor` — audit konfigurasi produksi SecurePayload.
 *
 * Menjalankan DoctorChecks (KEK, secret HMAC env, direktori storage, replayStore
 * multi-server, retensi arsip vs destroy_after) lalu merender hasil sebagai tabel:
 *   [OK]/[WARN]/[FAIL] name — detail
 *
 * Exit code: FAILURE jika ada entri FAIL, SUCCESS selain itu (WARN dianggap perlu
 * perhatian tapi tidak menggagalkan).
 */
final class DoctorCommand extends Command
{
    protected static $defaultName = 'doctor';

    protected function configure(): void
    {
        $this->setDescription('Audit konfigurasi produksi: KEK, secret HMAC, storage dir, replayStore multi-server, retensi vs destroy');
        $this->setName('doctor');
        $this
            ->addOption('storage-dir', null, InputOption::VALUE_REQUIRED, 'Direktori penyimpanan file aman yang akan dicek writability/permission')
            ->addOption('retention-days', null, InputOption::VALUE_REQUIRED, 'Masa retensi arsip (hari) untuk check destroy_after', '90')
            ->addOption('dsn', null, InputOption::VALUE_REQUIRED, 'DSN PDO opsional untuk check retention vs destroy_after (mis. sqlite:/var/data/sp.db)')
            ->addOption('table', null, InputOption::VALUE_REQUIRED, 'Nama tabel kunci SQL', 'secure_keys')
            ->addOption('multi-server', null, InputOption::VALUE_NONE, 'Tandai deployment multi-server (mengaktifkan heuristik replayStore)')
            ->addOption('secret-env-prefix', null, InputOption::VALUE_REQUIRED, 'Prefix nama env secret HMAC', 'SECUREPAYLOAD_');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $options = [];

        $storageDir = $input->getOption('storage-dir');
        if (is_string($storageDir) && $storageDir !== '') {
            $options['storage_dir'] = $storageDir;
        }

        $retention = $input->getOption('retention-days');
        if (is_string($retention) && $retention !== '' && is_numeric($retention)) {
            $options['retention_days'] = (int) $retention;
        }

        $options['multi_server'] = (bool) $input->getOption('multi-server');

        $prefix = $input->getOption('secret-env-prefix');
        if (is_string($prefix) && $prefix !== '') {
            $options['secret_env_prefix'] = $prefix;
        }

        $table = $input->getOption('table');
        if (is_string($table) && $table !== '') {
            $options['table'] = $table;
        }

        // Entri tambahan di luar DoctorChecks: kegagalan koneksi DB dilaporkan sebagai
        // FAIL tersendiri agar audit tetap jalan untuk check lainnya.
        $entries = [];
        $dsn = $input->getOption('dsn');
        if (is_string($dsn) && $dsn !== '') {
            try {
                $pdo = new PDO($dsn, null, null, [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                ]);
                $options['pdo'] = $pdo;
            } catch (PDOException $e) {
                $entries[] = [
                    'name' => 'db_connection',
                    'level' => 'fail',
                    'detail' => 'Gagal koneksi DSN: ' . $e->getMessage(),
                ];
            }
        }

        foreach ((new DoctorChecks())->run([], $options) as $e) {
            $entries[] = $e;
        }

        $hasFail = false;
        foreach ($entries as $entry) {
            /** @var string $level */
            $level = (string) ($entry['level'] ?? 'ok');
            $name = (string) ($entry['name'] ?? '?');
            $detail = (string) ($entry['detail'] ?? '');
            $tag = strtoupper($level);
            if ($level === 'fail') {
                $hasFail = true;
                $output->writeln("<error>[$tag]</error> $name — $detail");
            } elseif ($level === 'warn') {
                $output->writeln("<comment>[$tag]</comment> $name — $detail");
            } else {
                $output->writeln("<info>[$tag]</info> $name — $detail");
            }
        }

        return $hasFail ? Command::FAILURE : Command::SUCCESS;
    }
}
