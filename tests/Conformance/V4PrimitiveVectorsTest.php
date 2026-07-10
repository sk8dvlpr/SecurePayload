<?php

declare(strict_types=1);

namespace SecurePayload\Tests\Conformance;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

/**
 * Primitive vectors protokol v4 (minimal) — logika sama v3 dengan version string "4".
 */
final class V4PrimitiveVectorsTest extends TestCase
{
    private static function root(): string
    {
        return dirname(__DIR__, 2) . '/docs/fixtures/v4';
    }

    public function testHmacMessageV4(): void
    {
        $path = self::root() . '/primitive/hmac-message.json';
        if (!is_file($path)) {
            $this->markTestSkipped('fixture v4 belum ada');
        }
        $data = json_decode((string) file_get_contents($path), true);
        $this->assertIsArray($data);
        $in = $data['input'];
        $qStr = SecurePayload::canonicalQuery($in['query']);
        $msg = SecurePayload::hmacMessage(
            $in['version'],
            $in['clientId'],
            $in['keyId'],
            $in['timestamp'],
            $in['nonce_b64'],
            $in['method'],
            $in['path'],
            $qStr,
            $in['body_digest_b64']
        );
        $this->assertSame($data['expected']['message'], $msg);
        $this->assertStringStartsWith("v4\n", $msg);
    }

    public function testDefaultVersionIs4(): void
    {
        $this->assertSame('4', SecurePayload::DEFAULT_VERSION);
    }
}
