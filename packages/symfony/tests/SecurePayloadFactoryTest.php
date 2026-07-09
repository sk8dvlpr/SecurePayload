<?php
declare(strict_types=1);

namespace SecurePayload\Symfony\Tests;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;
use SecurePayload\Symfony\DependencyInjection\Configuration;
use SecurePayload\Symfony\SecurePayloadFactory;
use Symfony\Component\Config\Definition\Processor;

final class SecurePayloadFactoryTest extends TestCase
{
    public function testDefaultConfiguration(): void
    {
        $processor = new Processor();
        $config = $processor->processConfiguration(new Configuration(), [[]]);

        $this->assertSame('both', $config['mode']);
        $this->assertSame('3', $config['version']);
    }

    public function testCreateClient(): void
    {
        $config = [
            'mode' => 'hmac',
            'version' => '3',
            'sign_alg' => 'hmac',
            'client' => [
                'client_id' => 'c1',
                'key_id' => 'k1',
                'hmac_secret' => str_repeat('c', 32),
            ],
        ];

        $client = SecurePayloadFactory::createClient($config);
        $this->assertInstanceOf(SecurePayload::class, $client);
    }

    public function testCreateServerEnvProvider(): void
    {
        $config = [
            'mode' => 'both',
            'version' => '3',
            'server' => ['key_provider' => 'env'],
        ];

        $server = SecurePayloadFactory::createServer($config);
        $this->assertInstanceOf(SecurePayload::class, $server);
    }
}
