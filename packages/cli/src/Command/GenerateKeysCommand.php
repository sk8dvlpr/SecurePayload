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
            ->addOption('table', null, InputOption::VALUE_REQUIRED, 'Nama tabel SQL', 'secure_keys');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $manager = new KeyManager();
        $clientId = (string) $input->getArgument('clientId');
        $keyId = (string) $input->getArgument('keyId');
        $kek = $input->getOption('kek');
        $kekId = is_string($kek) && $kek !== '' ? $kek : null;
        $table = (string) $input->getOption('table');

        $result = $manager->generateKeyPair($clientId, $keyId, $kekId);

        if ($input->getOption('ed25519')) {
            $ed = $manager->generateEd25519KeyPair();
            $output->writeln('Ed25519 client public (DB): ' . $ed['publicB64']);
            $output->writeln('Ed25519 client secret (client env): ' . $ed['secretB64']);
        }

        if ($input->getOption('ed25519-server')) {
            $edSrv = $manager->generateEd25519ServerKeyPair();
            $output->writeln('Ed25519 server public (client env): ' . $edSrv['publicB64']);
            $output->writeln('Ed25519 server secret (server DB): ' . $edSrv['secretB64']);
        }

        $output->writeln($result->toSqlInsert($table));
        $output->writeln('<info>HMAC secret (simpan aman): ' . $result->hmacSecret . '</info>');
        if ($result->aeadKeyB64 !== null && $result->aeadKeyB64 !== '') {
            $output->writeln('<info>AEAD key b64: ' . $result->aeadKeyB64 . '</info>');
        }

        return Command::SUCCESS;
    }
}
