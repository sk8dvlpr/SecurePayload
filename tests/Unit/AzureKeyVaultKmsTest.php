<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SecurePayload\KMS\AzureKeyVaultKms;

/**
 * Unit test AzureKeyVaultKms (Phase 15) — klien palsu tanpa SDK/jaringan.
 */
final class AzureKeyVaultKmsTest extends TestCase
{
    private const AAD = ['client_id' => 'c1', 'key_id' => 'k1', 'purpose' => 'securepayload-aead-key'];

    private function fakeClient(): object
    {
        return new class {
            /** @var array<string,array{pt:string,ctx:array<string,string>}> */
            public array $store = [];
            private int $n = 0;

            /** @param array<string,mixed> $args */
            public function encrypt(array $args): object
            {
                $blob = 'az-ct-' . (++$this->n);
                /** @var array<string,string> $ctx */
                $ctx = $args['additionalAuthenticatedData'] ?? [];
                $this->store[$blob] = ['pt' => (string) ($args['value'] ?? ''), 'ctx' => $ctx];
                return self::result(['result' => $blob]);
            }

            /** @param array<string,mixed> $args */
            public function decrypt(array $args): object
            {
                $blob = (string) ($args['value'] ?? '');
                if (!isset($this->store[$blob])) {
                    throw new \RuntimeException('unknown ciphertext');
                }
                $entry = $this->store[$blob];
                /** @var array<string,string> $ctx */
                $ctx = $args['additionalAuthenticatedData'] ?? [];
                if ($entry['ctx'] !== $ctx) {
                    throw new \RuntimeException('Azure Key Vault: AAD mismatch');
                }
                return self::result(['result' => $entry['pt']]);
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
        $kms = new AzureKeyVaultKms($this->fakeClient());
        $secret = random_bytes(32);

        $blob = $kms->wrap('my-key', $secret, self::AAD);
        $this->assertNotSame('', $blob);

        $recovered = $kms->unwrap('my-key', $blob, self::AAD);
        $this->assertSame(bin2hex($secret), bin2hex($recovered));
    }

    public function testUnwrapWithDifferentAadFails(): void
    {
        $kms = new AzureKeyVaultKms($this->fakeClient());
        $blob = $kms->wrap('my-key', random_bytes(32), self::AAD);

        $this->expectException(RuntimeException::class);
        $kms->unwrap('my-key', $blob, ['client_id' => 'c1', 'key_id' => 'k1', 'purpose' => 'lain']);
    }

    public function testDefaultKeyNameUsedWhenEmpty(): void
    {
        $kms = new AzureKeyVaultKms($this->fakeClient(), 'default-key');
        $secret = random_bytes(32);
        $blob = $kms->wrap('', $secret, self::AAD);
        $recovered = $kms->unwrap('', $blob, self::AAD);
        $this->assertSame(bin2hex($secret), bin2hex($recovered));
    }

    public function testMissingMethodsRejected(): void
    {
        $this->expectException(RuntimeException::class);
        new AzureKeyVaultKms(new \stdClass());
    }

    public function testEmptyKekIdWithoutDefaultThrows(): void
    {
        $kms = new AzureKeyVaultKms($this->fakeClient());
        $this->expectException(RuntimeException::class);
        $kms->wrap('', random_bytes(32), self::AAD);
    }
}
