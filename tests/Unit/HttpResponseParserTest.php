<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\Http\HttpResponseParser;

final class HttpResponseParserTest extends TestCase
{
    public function testFromPartsDecodesJsonBody(): void
    {
        $result = HttpResponseParser::fromParts(200, ['Content-Type' => 'application/json'], '{"a":1}');
        $this->assertSame(['a' => 1], $result['body']);
    }

    public function testParseHeaderBlock(): void
    {
        $headers = HttpResponseParser::parseHeaderBlock("HTTP/1.1 200 OK\r\nX-Test: abc\r\n");
        $this->assertSame('abc', $headers['X-Test']);
    }
}
