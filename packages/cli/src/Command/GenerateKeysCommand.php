<?php
declare(strict_types=1);

namespace SecurePayload\Cli\Command;

use SecurePayload\KMS\KeyManager;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class GenerateKeysCommand extends Command
{
    protected static $defaultName = 'keys:generate';

    protected function configure(): void
    {
        $this->setDescription('Generate HMAC/AEAD key pair dan cetak SQL INSERT');
        $this->setName('keys:generate');
        $this
            ->addArgument('clientId', InputArgument::REQUIRED, 'Client ID')
            ->addArgument('keyId', InputArgument::REQUIRED, 'Key ID')
            ->addOption('kek', null, InputOption::VALUE_REQUIRED, 'KEK ID untuk wrap AEAD key')
            ->addOption('ed25519', null, InputOption::VALUE_NONE, 'Sertakan pasangan Ed25519 client')
            ->addOption('ed25519-server', null, InputOption::VALUE_NONE, 'Sertakan pasangan Ed25519 server')
            ->addOption('table', null, InputOption::VALUE_REQUIRED, 'Nama tabel SQL', 'secure_keys')
            ->addOption('output-file', 'o', InputOption::VALUE_REQUIRED, 'Tulis secret ke file (mode 0600); stdout hanya ringkasan')
            ->addOption('show-secrets', null, InputOption::VALUE_NONE, 'Cetak secret ke stdout (TIDAK disarankan)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $manager = new KeyManager();
        $clientId = (string) $input->getArgument('clientId');
        $keyId = (string) $input->getArgument('keyId');
        $kek = $input->getOption('kek');
        $kekId = is_string($kek) && $kek !== '' ? $kek : null;
        $table = (string) $input->getOption('table');
        $outFile = $input->getOption('output-file');
        $showSecrets = (bool) $input->getOption('show-secrets');

        $result = $manager->generateKeyPair($clientId, $keyId, $kekId);

        $secretLines = [];
        $secretLines[] = 'HMAC secret: ' . $result->hmacSecret;
        if ($result->aeadKeyB64 !== null && $result->aeadKeyB64 !== '') {
            $secretLines[] = 'AEAD key b64: ' . $result->aeadKeyB64;
        }

        if ($input->getOption('ed25519')) {
            $ed = $manager->generateEd25519KeyPair();
            $secretLines[] = 'Ed25519 client public (DB): ' . $ed['publicB64'];
            $secretLines[] = 'Ed25519 client secret (client env): ' . $ed['secretB64'];
        }

        if ($input->getOption('ed25519-server')) {
            $edSrv = $manager->generateEd25519ServerKeyPair();
            $secretLines[] = 'Ed25519 server public (client env): ' . $edSrv['publicB64'];
            $secretLines[] = 'Ed25519 server secret (server DB): ' . $edSrv['secretB64'];
        }

        $sql = $result->toSqlInsert($table);
        $secretLines[] = 'SQL:';
        $secretLines[] = $sql;

        if (is_string($outFile) && $outFile !== '') {
            $written = @file_put_contents($outFile, implode("\n", $secretLines) . "\n");
            if ($written === false) {
                $output->writeln('<error>Gagal menulis --output-file: ' . $outFile . '</error>');
                return Command::FAILURE;
            }
            @chmod($outFile, 0600);
            $output->writeln('<info>Secrets ditulis ke ' . $outFile . ' (mode 0600)</info>');
            $output->writeln('<info>clientId=' . $clientId . ' keyId=' . $keyId . ' (secret tidak dicetak ke stdout)</info>');
            return Command::SUCCESS;
        }

        if ($showSecrets) {
            foreach ($secretLines as $line) {
                $output->writeln($line);
            }
            $output->writeln('<comment>Peringatan: secret dicetak ke stdout. Prefer --output-file.</comment>');
            return Command::SUCCESS;
        }

        $output->writeln('<comment>SQL + secret disembunyikan (berisi kunci). Gunakan --output-file=PATH atau --show-secrets.</comment>');
        $output->writeln('<info>clientId=' . $clientId . ' keyId=' . $keyId . '</info>');

        return Command::SUCCESS;
    }
}
