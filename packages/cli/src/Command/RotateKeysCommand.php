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
            ->addOption('table', null, InputOption::VALUE_REQUIRED, 'Nama tabel SQL', 'secure_keys');
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

        $rotation = $manager->rotateKey(
            $clientId,
            $currentKeyId,
            $newKeyId,
            $grace,
            $kekId,
            (bool) $input->getOption('ed25519'),
            (bool) $input->getOption('ed25519-server')
        );

        $output->writeln($rotation->toSqlUpdateRetiring($table));
        $output->writeln($rotation->toSqlInsertNew($table));
        $output->writeln('<info>Grace ends at: ' . date('c', $rotation->graceEndsAt) . '</info>');
        $output->writeln('<info>New key ID: ' . $rotation->newKeyId . '</info>');
        if ($rotation->ed25519SecretKeyB64 !== null) {
            $output->writeln('Ed25519 client secret (distribusi ke client): ' . $rotation->ed25519SecretKeyB64);
        }

        return Command::SUCCESS;
    }
}
