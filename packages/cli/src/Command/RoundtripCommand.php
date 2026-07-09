<?php
declare(strict_types=1);

namespace SecurePayload\Cli\Command;

use SecurePayload\KMS\KeyManager;
use SecurePayload\SecurePayload;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class RoundtripCommand extends Command
{
    protected static $defaultName = 'test:roundtrip';

    protected function configure(): void
    {
        $this
            ->setName('test:roundtrip')
            ->setDescription('In-process client buildHeadersAndBody → server verify')
            ->addOption('mode', null, InputOption::VALUE_REQUIRED, 'Mode', 'both')
            ->addOption('protocol-version', null, InputOption::VALUE_REQUIRED, 'Protocol version', SecurePayload::DEFAULT_VERSION)
            ->addOption('sign-alg', null, InputOption::VALUE_REQUIRED, 'signAlg', 'hmac')
            ->addOption('url', null, InputOption::VALUE_REQUIRED, 'URL untuk canonical', 'https://api.test/v1/pay')
            ->addOption('path', null, InputOption::VALUE_REQUIRED, 'Path server verify', '/v1/pay')
            ->addOption('query', null, InputOption::VALUE_REQUIRED, 'Query string', '');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $mode = (string) $input->getOption('mode');
        $version = (string) $input->getOption('protocol-version');
        $signAlg = (string) $input->getOption('sign-alg');
        $url = (string) $input->getOption('url');
        $path = (string) $input->getOption('path');
        $query = (string) ($input->getOption('query') ?? '');

        $manager = new KeyManager();
        $keys = $manager->generateKeyPair('cli-roundtrip', 'key-v1');

        $clientOpts = [
            'mode' => $mode,
            'version' => $version,
            'signAlg' => $signAlg,
            'clientId' => $keys->clientId,
            'keyId' => $keys->keyId,
        ];

        if ($mode !== 'aead') {
            $clientOpts['hmacSecretRaw'] = $keys->hmacSecret;
        }
        if ($mode !== 'hmac') {
            $clientOpts['aeadKeyB64'] = $keys->aeadKeyB64;
        }

        $client = new SecurePayload($clientOpts);

        $server = new SecurePayload([
            'mode' => $mode,
            'version' => $version,
            'signAlg' => $signAlg,
            'keyLoader' => static function (string $cid, string $kid) use ($keys): array {
                return [
                    'hmacSecret' => $keys->hmacSecret,
                    'aeadKeyB64' => $keys->aeadKeyB64,
                    'ed25519PublicKeyB64' => null,
                    'ed25519SecretKeyServerB64' => null,
                ];
            },
        ]);

        $payload = ['ping' => 'roundtrip', 'ts' => time()];
        [$headers, $body] = $client->buildHeadersAndBody($url, 'POST', $payload);
        $verify = $server->verify($headers, $body, 'POST', $path, $query);

        $output->writeln(json_encode([
            'ok' => $verify['ok'] ?? false,
            'status' => $verify['status'] ?? null,
            'error' => $verify['error'] ?? null,
            'mode' => $mode,
            'version' => $version,
            'sign_alg' => $signAlg,
        ], JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT));

        return ($verify['ok'] ?? false) ? Command::SUCCESS : Command::FAILURE;
    }
}
