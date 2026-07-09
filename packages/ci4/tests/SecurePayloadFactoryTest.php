<?php
declare(strict_types=1);

namespace SecurePayload\Ci4\Tests;

use PHPUnit\Framework\TestCase;
use SecurePayload\Ci4\SecurePayloadFactory;
use SecurePayload\SecurePayload;

final class SecurePayloadFactoryTest extends TestCase
{
    public function testDefaultConfigHasVersionThree(): void
    {
        $config = SecurePayloadFactory::defaultConfig();
        $this->assertSame('3', $config['version']);
    }

    public function testCreateClient(): void
    {
        $config = SecurePayloadFactory::defaultConfig();
        $config['client']['client_id'] = 'ci4-client';
        $config['client']['key_id'] = 'key-1';
        $config['client']['hmac_secret'] = str_repeat('d', 32);

        $client = SecurePayloadFactory::createClient($config);
        $this->assertInstanceOf(SecurePayload::class, $client);
    }

    public function testNormalizeHeaders(): void
    {
        $out = SecurePayloadFactory::normalizeHeaders(['x-nonce' => 'n1']);
        $this->assertSame(['X-NONCE' => 'n1'], $out);
    }
}
