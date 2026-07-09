<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Conformance;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

final class NegativeVectorsTest extends TestCase
{
    /**
     * @return iterable<string, array{0:string}>
     */
    public function negativeFixtureProvider(): iterable
    {
        foreach (FixtureLoader::listJsonFiles('negative') as $path) {
            $data = FixtureLoader::loadFile($path);
            yield $data['id'] => [$path];
        }
    }

    /**
     * @dataProvider negativeFixtureProvider
     */
    public function testNegativeFixtureRejected(string $path): void
    {
        $fixture = FixtureLoader::loadFile($path);
        $keys = FixtureLoader::loadKeys($fixture['keys_ref'] ?? 'standard');
        $config = $fixture['config'];
        $config['protocol_version'] = $fixture['protocol_version'];
        if (isset($fixture['server_config'])) {
            $config['server_config'] = $fixture['server_config'];
        }
        $fixed = $fixture['fixed'];
        $req = $fixture['request'];
        $headers = $fixture['expected']['headers'];
        $body = $fixture['expected']['body'];

        $server = new SecurePayload(FixtureLoader::serverOpts($keys, $config, $fixed));
        $verify = $server->verify($headers, $body, $req['method'], $req['path'], $req['query']);
        $this->assertFalse($verify['ok'], 'Expected verify to fail for ' . $fixture['id']);
    }
}
