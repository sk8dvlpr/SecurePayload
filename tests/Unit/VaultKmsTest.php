<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SecurePayload\KMS\VaultKms;

/**
 * Unit test VaultKms (Phase 7) — memakai transport HTTP palsu (tanpa jaringan)
 * yang mensimulasikan Transit engine: ciphertext mengikat `context` (AAD).
 */
final class VaultKmsTest extends TestCase
{
    private const AAD = ['client_id' => 'c1', 'key_id' => 'k1', 'purpose' => 'securepayload-aead-key'];

    /**
     * Transport palsu mirip Vault Transit.
     *
     * @param array<string,array{pt:string,ctx:?string}> $store
     */
    private function fakeTransport(array &$store, int &$counter): callable
    {
        return function (string $method, string $url, array $headers, string $body) use (&$store, &$counter): array {
            $this->assertSame('POST', $method);
            $this->assertContains('X-Vault-Token: my-token', $headers);
            /** @var array<string,mixed> $payload */
            $payload = json_decode($body, true);

            if (strpos($url, '/encrypt/') !== false) {
                $id = 'vault:v1:' . (++$counter);
                $store[$id] = [
                    'pt' => (string) ($payload['plaintext'] ?? ''),
                    'ctx' => isset($payload['context']) ? (string) $payload['context'] : null,
                ];
                return ['status' => 200, 'body' => (string) json_encode(['data' => ['ciphertext' => $id]])];
            }
            if (strpos($url, '/decrypt/') !== false) {
                $ct = (string) ($payload['ciphertext'] ?? '');
                if (!isset($store[$ct])) {
                    return ['status' => 400, 'body' => (string) json_encode(['errors' => ['unknown ciphertext']])];
                }
                $entry = $store[$ct];
                $ctx = isset($payload['context']) ? (string) $payload['context'] : null;
                if ($entry['ctx'] !== $ctx) {
                    return ['status' => 400, 'body' => (string) json_encode(['errors' => ['context mismatch']])];
                }
                return ['status' => 200, 'body' => (string) json_encode(['data' => ['plaintext' => $entry['pt']]])];
            }
            return ['status' => 404, 'body' => '{}'];
        };
    }

    public function testWrapUnwrapRoundTrip(): void
    {
        $store = [];
        $counter = 0;
        $kms = new VaultKms('https://vault:8200', 'my-token', 'transit', $this->fakeTransport($store, $counter));

        $secret = random_bytes(32);
        $blob = $kms->wrap('mykek', $secret, self::AAD);
        $this->assertNotSame('', $blob);

        $recovered = $kms->unwrap('mykek', $blob, self::AAD);
        $this->assertSame(bin2hex($secret), bin2hex($recovered), 'unwrap harus mengembalikan plaintext asli.');
    }

    public function testUnwrapWithDifferentAadFails(): void
    {
        $store = [];
        $counter = 0;
        $kms = new VaultKms('https://vault:8200', 'my-token', 'transit', $this->fakeTransport($store, $counter));

        $blob = $kms->wrap('mykek', random_bytes(32), self::AAD);

        $this->expectException(RuntimeException::class);
        $kms->unwrap('mykek', $blob, ['client_id' => 'c1', 'key_id' => 'k1', 'purpose' => 'lain']);
    }

    public function testHttpErrorPropagates(): void
    {
        $transport = fn(string $m, string $u, array $h, string $b): array
            => ['status' => 403, 'body' => '{"errors":["permission denied"]}'];
        $kms = new VaultKms('https://vault:8200', 'bad-token', 'transit', $transport);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Vault HTTP 403');
        $kms->wrap('mykek', random_bytes(32), self::AAD);
    }
}
