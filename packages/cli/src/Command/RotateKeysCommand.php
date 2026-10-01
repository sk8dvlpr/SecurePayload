<?php
declare(strict_types=1);

namespace SecurePayload\Cli\Command;

use SecurePayload\KMS\KeyManager;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class RotateKeysCommand extends Command
{
    protected static $defaultName = 'keys:rotate';

    protected function configure(): void
    {
        $this->setDescription('Rotasi kunci: SQL UPDATE retiring + INSERT key baru');
        $this->setName('keys:rotate');
        $this
            ->addArgument('clientId', InputArgument::REQUIRED, 'Client ID')
            ->addArgument('currentKeyId', InputArgument::REQUIRED, 'Key ID yang akan di-retire')
            ->addOption('new-key-id', null, InputOption::VALUE_REQUIRED, 'Key ID baru (default auto)')
            ->addOption('grace', null, InputOption::VALUE_REQUIRED, 'Grace period detik', '86400')
            ->addOption('kek', null, InputOption::VALUE_REQUIRED, 'KEK ID untuk wrap AEAD key baru')
            ->addOption('ed25519', null, InputOption::VALUE_NONE, 'Sertakan Ed25519 client pada key baru')
            ->addOption('ed25519-server', null, InputOption::VALUE_NONE, 'Sertakan Ed25519 server pada key baru')
            ->addOption('table', null, InputOption::VALUE_REQUIRED, 'Nama tabel SQL', 'secure_keys')
            ->addOption('output-file', 'o', InputOption::VALUE_REQUIRED, 'Tulis secret ke file (mode 0600)')
            ->addOption('show-secrets', null, InputOption::VALUE_NONE, 'Cetak secret ke stdout (TIDAK disarankan)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $manager = new KeyManager();
        $clientId = (string) $input->getArgument('clientId');
        $currentKeyId = (string) $input->getArgument('currentKeyId');
        $newKeyIdOpt = $input->getOption('new-key-id');
        $newKeyId = is_string($newKeyIdOpt) && $newKeyIdOpt !== '' ? $newKeyIdOpt : null;
        $grace = (int) $input->getOption('grace');
        $kek = $input->getOption('kek');
        $kekId = is_string($kek) && $kek !== '' ? $kek : null;
        $table = (string) $input->getOption('table');
        $outFile = $input->getOption('output-file');
        $showSecrets = (bool) $input->getOption('show-secrets');

        $rotation = $manager->rotateKey(
            $clientId,
            $currentKeyId,
            $newKeyId,
            $grace,
            $kekId,
            (bool) $input->getOption('ed25519'),
            (bool) $input->getOption('ed25519-server')
        );

        $lines = [];
        $lines[] = $rotation->toSqlUpdateRetiring($table);
        $lines[] = $rotation->toSqlInsertNew($table);
        $lines[] = 'Grace ends at: ' . date('c', $rotation->graceEndsAt);
        $lines[] = 'New key ID: ' . $rotation->newKeyId;
        $lines[] = 'New HMAC: ' . $rotation->newKey->hmacSecret;
        if ($rotation->newKey->aeadKeyB64 !== null && $rotation->newKey->aeadKeyB64 !== '') {
            $lines[] = 'New AEAD b64: ' . $rotation->newKey->aeadKeyB64;
        }
        if ($rotation->ed25519SecretKeyB64 !== null) {
            $lines[] = 'Ed25519 client secret (distribusi ke client): ' . $rotation->ed25519SecretKeyB64;
        }

        if (is_string($outFile) && $outFile !== '') {
            $written = @file_put_contents($outFile, implode("\n", $lines) . "\n");
            if ($written === false) {
                $output->writeln('<error>Gagal menulis --output-file: ' . $outFile . '</error>');
                return Command::FAILURE;
            }
            @chmod($outFile, 0600);
            $output->writeln('<info>Secrets ditulis ke ' . $outFile . ' (mode 0600)</info>');
            $output->writeln('<info>New key ID: ' . $rotation->newKeyId . '</info>');
            return Command::SUCCESS;
        }

        if ($showSecrets) {
            foreach ($lines as $line) {
                $output->writeln($line);
            }
            $output->writeln('<comment>Peringatan: secret dicetak ke stdout. Prefer --output-file.</comment>');
            return Command::SUCCESS;
        }

        $output->writeln('<info>Grace ends at: ' . date('c', $rotation->graceEndsAt) . '</info>');
        $output->writeln('<info>New key ID: ' . $rotation->newKeyId . '</info>');
        $output->writeln('<comment>SQL + secret disembunyikan. Gunakan --output-file atau --show-secrets.</comment>');

        return Command::SUCCESS;
    }
}
