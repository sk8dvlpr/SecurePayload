<?php
declare(strict_types=1);

namespace SecurePayload\Cli\Tests;

use PHPUnit\Framework\TestCase;
use SecurePayload\Cli\Application;
use Symfony\Component\Console\Tester\CommandTester;

final class CliCommandsTest extends TestCase
{
    public function testRoundtripSucceedsForHmacMode(): void
    {
        $app = new Application();
        $command = $app->find('test:roundtrip');
        $tester = new CommandTester($command);

        $exitCode = $tester->execute([
            '--mode' => 'hmac',
            '--protocol-version' => '3',
        ]);

        $this->assertSame(0, $exitCode);
        $this->assertStringContainsString('"ok": true', $tester->getDisplay());
    }

    public function testGenerateKeysMasksSecretsByDefault(): void
    {
        $app = new Application();
        $command = $app->find('keys:generate');
        $tester = new CommandTester($command);

        $exitCode = $tester->execute([
            'clientId' => 'cli_test',
            'keyId' => 'key_1',
        ]);

        $this->assertSame(0, $exitCode);
        $display = $tester->getDisplay();
        $this->assertStringNotContainsString('INSERT INTO', $display);
        $this->assertStringContainsString('--output-file', $display);
    }

    public function testGenerateKeysShowSecretsOutputsSql(): void
    {
        $app = new Application();
        $command = $app->find('keys:generate');
        $tester = new CommandTester($command);

        $exitCode = $tester->execute([
            'clientId' => 'cli_test',
            'keyId' => 'key_1',
            '--show-secrets' => true,
        ]);

        $this->assertSame(0, $exitCode);
        $this->assertStringContainsString('INSERT INTO', $tester->getDisplay());
    }
}
