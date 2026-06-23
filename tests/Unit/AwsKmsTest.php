<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SecurePayload\KMS\AwsKms;

/**
 * Unit test AwsKms (Phase 7) — memakai klien KMS palsu (tanpa SDK/jaringan) yang
 * mensimulasikan binding EncryptionContext (AAD).
 */
final class AwsKmsTest extends TestCase
{
    private const AAD = ['client_id' => 'c1', 'key_id' => 'k1', 'purpose' => 'securepayload-aead-key'];

    /** Klien KMS palsu: encrypt/decrypt in-memory, mengikat EncryptionContext. */
    private function fakeClient(): object
    {
        return new class {
            /** @var array<string,array{pt:string,ctx:array<string,string>}> */
            public array $store = [];
            private int $n = 0;

            /** @param array<string,mixed> $args */
            public function encrypt(array $args): object
            {
                $blob = 'ct-' . (++$this->n);
                /** @var array<string,string> $ctx */
                $ctx = $args['EncryptionContext'] ?? [];
                $this->store[$blob] = ['pt' => (string) ($args['Plaintext'] ?? ''), 'ctx' => $ctx];
                return self::result(['CiphertextBlob' => $blob]);
            }

            /** @param array<string,mixed> $args */
            public function decrypt(array $args): object
            {
                $blob = (string) ($args['CiphertextBlob'] ?? '');
                if (!isset($this->store[$blob])) {
                    throw new \RuntimeException('unknown ciphertext');
                }
                $entry = $this->store[$blob];
                /** @var array<string,string> $ctx */
                $ctx = $args['EncryptionContext'] ?? [];
                if ($entry['ctx'] !== $ctx) {
                    throw new \RuntimeException('InvalidCiphertextException: context mismatch');
                }
                return self::result(['Plaintext' => $entry['pt']]);
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
        $kms = new AwsKms($this->fakeClient());
        $secret = random_bytes(32);

        $blob = $kms->wrap('arn:aws:kms:...:key/abc', $secret, self::AAD);
        $this->assertNotSame('', $blob);

        $recovered = $kms->unwrap('arn:aws:kms:...:key/abc', $blob, self::AAD);
        $this->assertSame(bin2hex($secret), bin2hex($recovered));
    }

    public function testUnwrapWithDifferentAadFails(): void
    {
        $kms = new AwsKms($this->fakeClient());
        $blob = $kms->wrap('kid', random_bytes(32), self::AAD);

        $this->expectException(RuntimeException::class);
        $kms->unwrap('kid', $blob, ['client_id' => 'c1', 'key_id' => 'k1', 'purpose' => 'lain']);
    }

    public function testDefaultKekIdUsedWhenEmpty(): void
    {
        $kms = new AwsKms($this->fakeClient(), 'default-kek');
        $secret = random_bytes(32);
        $blob = $kms->wrap('', $secret, self::AAD); // kekId kosong → pakai default
        $recovered = $kms->unwrap('', $blob, self::AAD);
        $this->assertSame(bin2hex($secret), bin2hex($recovered));
    }

    public function testMissingMethodsRejected(): void
    {
        $this->expectException(RuntimeException::class);
        // Objek tanpa encrypt()/decrypt().
        new AwsKms(new \stdClass());
    }

    public function testEmptyKekIdWithoutDefaultThrows(): void
    {
        $kms = new AwsKms($this->fakeClient());
        $this->expectException(RuntimeException::class);
        $kms->wrap('', random_bytes(32), self::AAD);
    }
}
