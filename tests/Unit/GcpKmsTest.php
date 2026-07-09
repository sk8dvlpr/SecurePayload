<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SecurePayload\KMS\GcpKms;

/**
 * Unit test GcpKms (Phase 15) — klien palsu tanpa SDK/jaringan, mensimulasikan
 * binding additionalAuthenticatedData (AAD).
 */
final class GcpKmsTest extends TestCase
{
    private const AAD = ['client_id' => 'c1', 'key_id' => 'k1', 'purpose' => 'securepayload-aead-key'];

    private function fakeClient(): object
    {
        return new class {
            /** @var array<string,array{pt:string,aad:string}> */
            public array $store = [];
            private int $n = 0;

            /** @param array<string,mixed> $args */
            public function encrypt(array $args): object
            {
                $blob = 'gcp-ct-' . (++$this->n);
                $this->store[$blob] = [
                    'pt' => (string) ($args['plaintext'] ?? ''),
                    'aad' => (string) ($args['additionalAuthenticatedData'] ?? ''),
                ];
                return self::result(['ciphertext' => $blob]);
            }

            /** @param array<string,mixed> $args */
            public function decrypt(array $args): object
            {
                $blob = (string) ($args['ciphertext'] ?? '');
                if (!isset($this->store[$blob])) {
                    throw new \RuntimeException('unknown ciphertext');
                }
                $entry = $this->store[$blob];
                $aad = (string) ($args['additionalAuthenticatedData'] ?? '');
                if ($entry['aad'] !== $aad) {
                    throw new \RuntimeException('GCP KMS: AAD mismatch');
                }
                return self::result(['plaintext' => $entry['pt']]);
            }

            /** @param array<string,mixed> $data */
            private static function result(array $data): object
            {
                return new class($data) {
                    /** @param array<string,mixed> $d */
                    public function __construct(private array $d)
                    {
                    }

                    /** @return mixed */
                    public function get(string $k)
                    {
                        return $this->d[$k] ?? null;
                    }
                };
            }
        };
    }

    public function testWrapUnwrapRoundTrip(): void
    {
        $kms = new GcpKms($this->fakeClient());
        $secret = random_bytes(32);

        $blob = $kms->wrap('projects/p/locations/l/keyRings/r/cryptoKeys/k', $secret, self::AAD);
        $this->assertNotSame('', $blob);

        $recovered = $kms->unwrap('projects/p/locations/l/keyRings/r/cryptoKeys/k', $blob, self::AAD);
        $this->assertSame(bin2hex($secret), bin2hex($recovered));
    }

    public function testUnwrapWithDifferentAadFails(): void
    {
        $kms = new GcpKms($this->fakeClient());
        $blob = $kms->wrap('projects/p/locations/l/keyRings/r/cryptoKeys/k', random_bytes(32), self::AAD);

        $this->expectException(RuntimeException::class);
        $kms->unwrap('projects/p/locations/l/keyRings/r/cryptoKeys/k', $blob, [
            'client_id' => 'c1', 'key_id' => 'k1', 'purpose' => 'lain',
        ]);
    }

    public function testDefaultKekIdUsedWhenEmpty(): void
    {
        $kms = new GcpKms($this->fakeClient(), 'projects/p/locations/l/keyRings/r/cryptoKeys/default');
        $secret = random_bytes(32);
        $blob = $kms->wrap('', $secret, self::AAD);
        $recovered = $kms->unwrap('', $blob, self::AAD);
        $this->assertSame(bin2hex($secret), bin2hex($recovered));
    }

    public function testMissingMethodsRejected(): void
    {
        $this->expectException(RuntimeException::class);
        new GcpKms(new \stdClass());
    }

    public function testEmptyKekIdWithoutDefaultThrows(): void
    {
        $kms = new GcpKms($this->fakeClient());
        $this->expectException(RuntimeException::class);
        $kms->wrap('', random_bytes(32), self::AAD);
    }
}
