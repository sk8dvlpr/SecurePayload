<?php
declare(strict_types=1);

namespace SecurePayload\Cli\Command;

use SecurePayload\KMS\EnvKeyProvider;
use SecurePayload\SecurePayload;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class DebugVerifyCommand extends Command
{
    protected static $defaultName = 'debug:verify';

    protected function configure(): void
    {
        $this
            ->setName('debug:verify')
            ->setDescription('Verifikasi request SecurePayload (output JSON)')
            ->addOption('headers', 'H', InputOption::VALUE_REQUIRED, 'Path file JSON headers')
            ->addOption('body', 'b', InputOption::VALUE_REQUIRED, 'Body string atau @file')
            ->addOption('method', 'm', InputOption::VALUE_REQUIRED, 'HTTP method')
            ->addOption('path', 'p', InputOption::VALUE_REQUIRED, 'Request path')
            ->addOption('query', 'q', InputOption::VALUE_REQUIRED, 'Query string', '')
            ->addOption('mode', null, InputOption::VALUE_REQUIRED, 'Mode server', 'both')
            ->addOption('protocol-version', null, InputOption::VALUE_REQUIRED, 'Protocol version', SecurePayload::DEFAULT_VERSION)
            ->addOption('sign-alg', null, InputOption::VALUE_REQUIRED, 'signAlg', 'hmac');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $headersPath = $input->getOption('headers');
        $bodyOpt = $input->getOption('body');
        $method = $input->getOption('method');
        $path = $input->getOption('path');

        if (!is_string($headersPath) || $headersPath === '') {
            $output->writeln(json_encode(['ok' => false, 'error' => 'Option --headers wajib'], JSON_THROW_ON_ERROR));

            return Command::FAILURE;
        }
        if (!is_string($method) || $method === '' || !is_string($path) || $path === '') {
            $output->writeln(json_encode(['ok' => false, 'error' => 'Option --method dan --path wajib'], JSON_THROW_ON_ERROR));

            return Command::FAILURE;
        }

        $headersRaw = file_get_contents($headersPath);
        if ($headersRaw === false) {
            $output->writeln(json_encode(['ok' => false, 'error' => 'Gagal baca headers file'], JSON_THROW_ON_ERROR));

            return Command::FAILURE;
        }

        /** @var array<string,string> $headers */
        $headers = json_decode($headersRaw, true, 512, JSON_THROW_ON_ERROR);
        $normalized = [];
        foreach ($headers as $k => $v) {
            $normalized[strtoupper((string) $k)] = (string) $v;
        }

        $body = $this->readBody(is_string($bodyOpt) ? $bodyOpt : '');
        $query = (string) ($input->getOption('query') ?? '');

        $provider = new EnvKeyProvider();
        $server = new SecurePayload([
            'mode' => (string) $input->getOption('mode'),
            'version' => (string) $input->getOption('protocol-version'),
            'signAlg' => (string) $input->getOption('sign-alg'),
            'keyLoader' => [$provider, 'load'],
        ]);

        $result = $server->verify($normalized, $body, $method, $path, $query);
        $output->writeln(json_encode($result, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT));

        return ($result['ok'] ?? false) ? Command::SUCCESS : Command::FAILURE;
    }

    private function readBody(string $bodyOpt): string
    {
        if ($bodyOpt === '') {
            $stdin = stream_get_contents(STDIN);

            return $stdin !== false ? $stdin : '';
        }

        if (str_starts_with($bodyOpt, '@')) {
            $path = substr($bodyOpt, 1);
            $content = file_get_contents($path);

            return $content !== false ? $content : '';
        }

        return $bodyOpt;
    }
}
