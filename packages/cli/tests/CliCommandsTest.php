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

    public function testGenerateKeysOutputsSql(): void
    {
        $app = new Application();
        $command = $app->find('keys:generate');
        $tester = new CommandTester($command);

        $exitCode = $tester->execute([
            'clientId' => 'cli-test',
            'keyId' => 'key-1',
        ]);

        $this->assertSame(0, $exitCode);
        $this->assertStringContainsString('INSERT INTO', $tester->getDisplay());
    }
}
