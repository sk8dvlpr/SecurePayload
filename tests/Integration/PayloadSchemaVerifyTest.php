<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Integration;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

/**
   * Integrasi penegakan `payloadSchema` di sisi server.
  
   * Mencakup: struktur salah → ok:false status 422 + event payload_schema_invalid
   * tertangkap hook onSecurityEvent; struktur valid → lolos; dan tanpa schema,
   * perilaku existing dipertahankan.
  */
final class PayloadSchemaVerifyTest extends TestCase
{
    private const HMAC_32 = 'test-hmac-secret-must-be-32bytes!!';

    /** @var list<array{event:string, context:array<string,mixed>}> */
    private array $events = [];

    private function client(): SecurePayload
    {
        return new SecurePayload([
            'mode' => 'hmac',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::HMAC_32,
        ]);
    }

    private function schema(): array
    {
        return [
            'type' => 'object',
            'required' => ['orderId', 'amount'],
            'properties' => [
                'orderId' => ['type' => 'string', 'pattern' => '/^ORD-/'],
                'amount' => ['type' => 'integer', 'minimum' => 1],
            ],
            'additionalProperties' => false,
        ];
    }

    /** Server dengan payloadSchema + hook event yang merekam semua event. */
    private function server(): SecurePayload
    {
        return new SecurePayload([
            'mode' => 'hmac',
            'payloadSchema' => $this->schema(),
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null],
            'onSecurityEvent' => function (string $event, array $context): void {
                $this->events[] = ['event' => $event, 'context' => $context];
            },
        ]);
    }

    /** @return array{0:array<string,string>,1:string} */
    private function buildRequest(array $payload): array
    {
        [$headers, $body] = $this->client()->buildHeadersAndBody('https://api/v1/orders', 'POST', $payload);
        return [$headers, $body];
    }

    public function testStrukturValidLolos(): void
    {
        $server = $this->server();
        [$headers, $body] = $this->buildRequest(['orderId' => 'ORD-1', 'amount' => 500]);

        $res = $server->verifyOrThrow($headers, $body, 'POST', '/v1/orders', []);
        $this->assertSame(['orderId' => 'ORD-1', 'amount' => 500], $res['json']);
        $this->assertSame([], $this->events, 'Payload valid tidak boleh memicu event apa pun.');
    }

    public function testFieldWajibKurang422DanEventTertangkap(): void
    {
        $server = $this->server();
        [$headers, $body] = $this->buildRequest(['orderId' => 'ORD-2']); // amount hilang

        $res = $server->verify($headers, $body, 'POST', '/v1/orders', []);
        $this->assertFalse($res['ok']);
        $this->assertSame(422, $res['status'], 'Pelanggaran skema harus UNPROCESSABLE.');
        $this->assertStringContainsString('payloadSchema', (string) ($res['error'] ?? ''));

        $this->assertCount(1, $this->events, 'Event payload_schema_invalid harus ter-emit tepat sekali.');
        $this->assertSame(SecurePayload::EVENT_PAYLOAD_SCHEMA_INVALID, $this->events[0]['event']);
        $this->assertSame('c1', $this->events[0]['context']['clientId']);
        $this->assertSame('k1', $this->events[0]['context']['keyId']);
        $this->assertArrayHasKey('error', $this->events[0]['context']);
    }

    public function testTipeSalahDanNilaiMinimumDitolak(): void
    {
        $server = $this->server();
        // orderId salah tipe (integer) & amount di bawah minimum.
        [$headers, $body] = $this->buildRequest(['orderId' => 99, 'amount' => 0]);

        $res = $server->verify($headers, $body, 'POST', '/v1/orders', []);
        $this->assertFalse($res['ok']);
        $this->assertSame(422, $res['status']);
        $this->assertStringContainsString("'orderId'", (string) ($res['error'] ?? ''), 'Error menyebut field pertama yang melanggar.');
    }

    public function testAdditionalPropertiesFalseDitolak(): void
    {
        $server = $this->server();
        [$headers, $body] = $this->buildRequest([
            'orderId' => 'ORD-3',
            'amount' => 10,
            'injected' => '<script>',
        ]);

        $res = $server->verify($headers, $body, 'POST', '/v1/orders', []);
        $this->assertFalse($res['ok']);
        $this->assertSame(422, $res['status']);
        $this->assertStringContainsString("'injected'", (string) ($res['error'] ?? ''));
    }

    public function testJsonRusakDenganSchemaAktifDitolak422(): void
    {
        $server = $this->server();
        // Request sah HMAC tetapi body bukan JSON → json null → ditolak saat schema aktif.
        [$headers, ] = $this->buildRequest(['x' => 1]);
        $digest = base64_encode(hash('sha256', 'bukan-json', true));
        $msg = SecurePayload::hmacMessage(
            '4',
            'c1',
            'k1',
            $headers[SecurePayload::HX_TIMESTAMP],
            $headers[SecurePayload::HX_NONCE],
            'POST',
            '/v1/orders',
            '',
            $digest
        );
        $sig = base64_encode(hash_hmac('sha256', $msg, self::HMAC_32, true));
        $h = array_merge($headers, [
            SecurePayload::HX_BODY_DIGEST => 'sha256=' . $digest,
            SecurePayload::HX_SIGNATURE => $sig,
        ]);

        $res = $server->verify($h, 'bukan-json', 'POST', '/v1/orders', []);
        $this->assertFalse($res['ok']);
        $this->assertSame(422, $res['status']);
        $this->assertCount(1, $this->events);
        $this->assertSame(SecurePayload::EVENT_PAYLOAD_SCHEMA_INVALID, $this->events[0]['event']);
    }

    public function testTanpaSchemaPerilakuExistingDipertahankan(): void
    {
        // Server TANPA payloadSchema: json rusak tetap dikembalikan apa adanya (null),
        // persis perilaku tanpa fitur - validasi skema murni opt-in.
        $server = new SecurePayload([
            'mode' => 'hmac',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null],
        ]);
        $client = $this->client();
        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['bebas' => ['struktur' => true]]);

        $res = $server->verifyOrThrow($headers, $body, 'POST', '/v1/x', []);
        $this->assertSame(['bebas' => ['struktur' => true]], $res['json']);
    }
}
