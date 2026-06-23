<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

/**
 * Unit test Phase 8 — hook observability `onSecurityEvent`.
 *
 * Memastikan event keamanan diemit pada skenario gagal yang relevan, context-nya
 * tidak membocorkan material rahasia, dan exception dari callback ditelan.
 */
final class SecurityEventTest extends TestCase
{
    private const HMAC_32 = 'test-hmac-secret-must-be-32bytes!!';

    /** @var list<array{event:string,context:array<string,mixed>}> */
    private array $events = [];

    private function aeadKeyB64(): string
    {
        return base64_encode(str_repeat("\x66", 32));
    }

    /** @param array<string,mixed> $extra */
    private function client(string $mode, array $extra = []): SecurePayload
    {
        return new SecurePayload(array_merge([
            'mode' => $mode,
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => self::HMAC_32,
            'aeadKeyB64' => $this->aeadKeyB64(),
        ], $extra));
    }

    /**
     * @param array<string,mixed> $extra
     * @param array{hmacSecret:?string,aeadKeyB64:?string}|null $keys
     */
    private function server(string $mode, array $extra = [], ?array $keys = null): SecurePayload
    {
        $keys = $keys ?? ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => $this->aeadKeyB64()];
        return new SecurePayload(array_merge([
            'mode' => $mode,
            'keyLoader' => fn($c, $k) => $keys,
            'onSecurityEvent' => function (string $event, array $context): void {
                $this->events[] = ['event' => $event, 'context' => $context];
            },
        ], $extra));
    }

    /** @return list<string> */
    private function eventNames(): array
    {
        return array_map(fn($e) => $e['event'], $this->events);
    }

    protected function setUp(): void
    {
        $this->events = [];
    }

    public function testSignatureInvalidEmitsEvent(): void
    {
        $client = $this->client('hmac');
        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['n' => 1]);
        $headers[SecurePayload::HX_SIGNATURE] = base64_encode('forged-signature-bytes-here-xx');

        $res = $this->server('hmac')->verify($headers, $body, 'POST', '/v1/x', []);
        $this->assertFalse($res['ok']);
        $this->assertContains(SecurePayload::EVENT_SIGNATURE_INVALID, $this->eventNames());
    }

    public function testKeyNotFoundEmitsEvent(): void
    {
        $client = $this->client('hmac');
        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['n' => 1]);

        // Server tidak punya secret untuk klien ini.
        $server = $this->server('hmac', [], ['hmacSecret' => null, 'aeadKeyB64' => null]);
        $res = $server->verify($headers, $body, 'POST', '/v1/x', []);
        $this->assertFalse($res['ok']);
        $this->assertContains(SecurePayload::EVENT_KEY_NOT_FOUND, $this->eventNames());
    }

    public function testTimestampInvalidEmitsEvent(): void
    {
        $client = $this->client('hmac');
        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['n' => 1]);
        $headers[SecurePayload::HX_TIMESTAMP] = (string) (time() - 100000); // jauh kedaluwarsa

        $res = $this->server('hmac')->verify($headers, $body, 'POST', '/v1/x', []);
        $this->assertFalse($res['ok']);
        $this->assertContains(SecurePayload::EVENT_TIMESTAMP_INVALID, $this->eventNames());
    }

    public function testReplayDetectedEmitsEvent(): void
    {
        $client = $this->client('hmac');
        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['n' => 1]);

        // replayStore yang selalu menganggap nonce sudah dipakai.
        $server = $this->server('hmac', ['replayStore' => fn($k, $ttl) => false]);
        $res = $server->verify($headers, $body, 'POST', '/v1/x', []);
        $this->assertFalse($res['ok']);
        $this->assertContains(SecurePayload::EVENT_REPLAY_DETECTED, $this->eventNames());
    }

    public function testDecryptFailedEmitsEvent(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium diperlukan');
        }
        $client = $this->client('aead');
        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['n' => 1]);

        // Rusak ciphertext di body.
        $decoded = json_decode($body, true);
        $blob = base64_decode($decoded['__aead_b64'], true);
        $blob[5] = $blob[5] === "\x00" ? "\x01" : "\x00";
        $decoded['__aead_b64'] = base64_encode($blob);
        $tampered = json_encode($decoded);

        $res = $this->server('aead')->verify($headers, $tampered, 'POST', '/v1/x', []);
        $this->assertFalse($res['ok']);
        $this->assertContains(SecurePayload::EVENT_DECRYPT_FAILED, $this->eventNames());
    }

    public function testNonceMismatchEmitsEvent(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium diperlukan');
        }
        $client = $this->client('aead');
        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['n' => 1]);
        $headers[SecurePayload::HX_AEAD_NONCE] = base64_encode(str_repeat("\x09", 24));

        $res = $this->server('aead')->verify($headers, $body, 'POST', '/v1/x', []);
        $this->assertFalse($res['ok']);
        $this->assertContains(SecurePayload::EVENT_NONCE_MISMATCH, $this->eventNames());
    }

    public function testContextNeverLeaksSecretOrPlaintext(): void
    {
        $client = $this->client('hmac');
        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['rahasia' => 'isi-payload-sensitif']);
        $headers[SecurePayload::HX_SIGNATURE] = base64_encode('forged-signature-bytes-here-xx');

        $this->server('hmac')->verify($headers, $body, 'POST', '/v1/x', []);
        $this->assertNotEmpty($this->events);

        foreach ($this->events as $e) {
            $blob = (string) json_encode($e['context']);
            $this->assertStringNotContainsString(self::HMAC_32, $blob, 'Context tidak boleh memuat HMAC secret.');
            $this->assertStringNotContainsString('isi-payload-sensitif', $blob, 'Context tidak boleh memuat plaintext.');
            // Hanya field non-rahasia yang diharapkan.
            $this->assertSame('c1', $e['context']['clientId'] ?? null);
            $this->assertSame('k1', $e['context']['keyId'] ?? null);
        }
    }

    public function testCallbackExceptionIsSwallowed(): void
    {
        $client = $this->client('hmac');
        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['n' => 1]);
        $headers[SecurePayload::HX_SIGNATURE] = base64_encode('forged-signature-bytes-here-xx');

        $server = new SecurePayload([
            'mode' => 'hmac',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null],
            'onSecurityEvent' => function (): void {
                throw new \RuntimeException('boom dari callback');
            },
        ]);

        // Tidak boleh melempar; tetap mengembalikan hasil verifikasi normal (gagal).
        $res = $server->verify($headers, $body, 'POST', '/v1/x', []);
        $this->assertFalse($res['ok']);
        $this->assertStringContainsString('Tanda Tangan', $res['error']);
    }

    public function testNoEventOnSuccess(): void
    {
        $client = $this->client('hmac');
        [$headers, $body] = $client->buildHeadersAndBody('https://api/v1/x', 'POST', ['n' => 1]);

        $res = $this->server('hmac')->verify($headers, $body, 'POST', '/v1/x', []);
        $this->assertTrue($res['ok']);
        $this->assertSame([], $this->events, 'Tidak ada event keamanan pada verifikasi sukses.');
    }
}
