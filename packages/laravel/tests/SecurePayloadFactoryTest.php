<?php
declare(strict_types=1);

namespace SecurePayload\Laravel\Tests;

use Orchestra\Testbench\TestCase;
use SecurePayload\Laravel\SecurePayloadFactory;
use SecurePayload\Laravel\SecurePayloadServiceProvider;
use SecurePayload\SecurePayload;

final class SecurePayloadFactoryTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SecurePayloadServiceProvider::class];
    }

    public function testConfigMerged(): void
    {
        $this->assertSame('3', config('securepayload.version'));
    }

    public function testCreateClientWithHmac(): void
    {
        $config = config('securepayload');
        $config['client']['client_id'] = 'client-a';
        $config['client']['key_id'] = 'key-v1';
        $config['client']['hmac_secret'] = str_repeat('b', 32);

        $client = SecurePayloadFactory::createClient($config);
        $this->assertInstanceOf(SecurePayload::class, $client);
    }

    public function testCreateServerWithEnvProvider(): void
    {
        $config = config('securepayload');
        $config['server']['key_provider'] = 'env';

        $server = SecurePayloadFactory::createServer($config);
        $this->assertInstanceOf(SecurePayload::class, $server);
    }

    public function testNormalizeHeaders(): void
    {
        $out = SecurePayloadFactory::normalizeHeaders(['X-Nonce' => ['abc']]);
        $this->assertSame(['X-NONCE' => 'abc'], $out);
    }
}
