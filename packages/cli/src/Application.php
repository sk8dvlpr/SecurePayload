<?php
declare(strict_types=1);

namespace SecurePayload\Cli;

use SecurePayload\Cli\Command\DebugVerifyCommand;
use SecurePayload\Cli\Command\GenerateKeysCommand;
use SecurePayload\Cli\Command\RotateKeysCommand;
use SecurePayload\Cli\Command\RoundtripCommand;
use Symfony\Component\Console\Application as SymfonyApplication;

final class Application extends SymfonyApplication
{
    public function __construct()
    {
        parent::__construct('securepayload', '1.0.0');
        $this->addCommands([
            new GenerateKeysCommand(),
            new RotateKeysCommand(),
            new DebugVerifyCommand(),
            new RoundtripCommand(),
        ]);
    }
}
