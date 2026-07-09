<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Conformance;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

final class WireVectorsTest extends TestCase
{
    /**
     * @return iterable<string, array{0:string}>
     */
    public function wireFixtureProvider(): iterable
    {
        foreach (FixtureLoader::listJsonFiles('wire') as $path) {
            $data = FixtureLoader::loadFile($path);
            yield $data['id'] => [$path];
        }
    }

    /**
     * @dataProvider wireFixtureProvider
     */
    public function testWireFixtureVerifyAndOptionalRoundtrip(string $path): void
    {
        $fixture = FixtureLoader::loadFile($path);
        $keys = FixtureLoader::loadKeys($fixture['keys_ref'] ?? 'standard');
        $config = $fixture['config'];
        $config['protocol_version'] = $fixture['protocol_version'];
        $fixed = $fixture['fixed'];
        $req = $fixture['request'];

        $client = new SecurePayload(FixtureLoader::clientOpts($keys, $config, $fixed, $req['extra_headers'] ?? []));
        $url = 'https://api.example' . $req['path'] . '?' . SecurePayload::canonicalQuery($req['query']);
        [$builtHeaders, $builtBody] = $client->buildHeadersAndBody($url, $req['method'], $req['payload'], $req['extra_headers'] ?? []);

        $this->assertSame($fixture['expected']['headers'], $builtHeaders, 'Client build headers mismatch');
        $this->assertSame($fixture['expected']['body'], $builtBody, 'Client build body mismatch');

        $server = new SecurePayload(FixtureLoader::serverOpts($keys, $config, $fixed));
        $verify = $server->verify($builtHeaders, $builtBody, $req['method'], $req['path'], $req['query']);
        $this->assertTrue($verify['ok'], $verify['error'] ?? 'verify failed');

        if (isset($fixture['expected']['response'])) {
            $respServer = new SecurePayload(FixtureLoader::serverOpts($keys, $config, $fixed, true));
            [$respHeaders, $respBody] = $respServer->buildResponse($builtHeaders, $fixture['expected']['response']['payload']);
            $this->assertSame($fixture['expected']['response']['headers'], $respHeaders);
            $this->assertSame($fixture['expected']['response']['body'], $respBody);

            $respClient = new SecurePayload(FixtureLoader::clientOpts($keys, $config, $fixed));
            $respVerify = $respClient->verifyResponse($respHeaders, $respBody, $builtHeaders[SecurePayload::HX_NONCE]);
            $this->assertTrue($respVerify['ok'], $respVerify['error'] ?? 'response verify failed');
            $this->assertSame($fixture['expected']['response']['payload'], $respVerify['json']);
        }
    }
}
