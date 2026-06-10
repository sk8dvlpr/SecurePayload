<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\KMS\LocalKms;
use RuntimeException;

final class LocalKmsTest extends TestCase
{
    private const KEK_ID = 'test-kek-1';
    private const STD_AAD = ['client_id' => 'c1', 'key_id' => 'k1', 'purpose' => 'test'];
    
    private array $envBackup = [];

    protected function setUp(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('libsodium extension required');
        }
        $this->envBackup = [];
        // Set standard valid env
        $kekRaw = random_bytes(32);
        $this->setEnv('SECURE_KEKS', self::KEK_ID);
        $this->setEnv('SECURE_KEK_' . self::KEK_ID . '_B64', base64_encode($kekRaw));
    }

    protected function tearDown(): void
    {
        foreach ($this->envBackup as $key => $value) {
            if ($value === false) {
                putenv($key);
            } else {
                putenv("$key=$value");
            }
        }
    }

    private function setEnv(string $key, string $value): void
    {
        $this->envBackup[$key] = getenv($key);
        putenv("$key=$value");
    }

    private function clearEnv(string $key): void
    {
        $this->envBackup[$key] = getenv($key);
        putenv($key);
    }

    public function testFromEnv_ValidConfig_ReturnsInstance(): void
    {
        $kms = LocalKms::fromEnv();
        $this->assertInstanceOf(LocalKms::class, $kms);
    }

    public function testFromEnv_MissingSecureKeks_ThrowsRuntimeException(): void
    {
        $this->clearEnv('SECURE_KEKS');
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('No KEKs configured');
        LocalKms::fromEnv();
    }

    public function testFromEnv_MissingKekEnvVar_ThrowsRuntimeException(): void
    {
        $this->setEnv('SECURE_KEKS', 'missing-kek');
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Missing SECURE_KEK_missing-kek_B64 in .env');
        LocalKms::fromEnv();
    }

    public function testFromEnv_InvalidBase64_ThrowsRuntimeException(): void
    {
        $this->setEnv('SECURE_KEK_' . self::KEK_ID . '_B64', 'invalid-b64!@#');
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('must be base64 of 32 bytes');
        LocalKms::fromEnv();
    }

    public function testFromEnv_KeyNot32Bytes_ThrowsRuntimeException(): void
    {
        $this->setEnv('SECURE_KEK_' . self::KEK_ID . '_B64', base64_encode('too-short'));
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('must be base64 of 32 bytes');
        LocalKms::fromEnv();
    }

    public function testWrapUnwrap_HappyPath_ReturnOriginalPlaintext(): void
    {
        $kms = LocalKms::fromEnv();
        $plaintext = 'secret-data';
        
        $wrapped = $kms->wrap(self::KEK_ID, $plaintext, self::STD_AAD);
        $unwrapped = $kms->unwrap(self::KEK_ID, $wrapped, self::STD_AAD);
        
        $this->assertSame($plaintext, $unwrapped);
    }

    public function testWrap_ProducesUniqueOutputEachCall(): void
    {
        $kms = LocalKms::fromEnv();
        $plaintext = 'secret-data';
        
        $wrapped1 = $kms->wrap(self::KEK_ID, $plaintext, self::STD_AAD);
        $wrapped2 = $kms->wrap(self::KEK_ID, $plaintext, self::STD_AAD);
        
        $this->assertNotSame($wrapped1, $wrapped2);
    }

    public function testUnwrap_WrongKey_ThrowsRuntimeException(): void
    {
        $kms1 = LocalKms::fromEnv();
        $wrapped = $kms1->wrap(self::KEK_ID, 'secret', self::STD_AAD);
        
        // Setup new env with different key
        $this->setEnv('SECURE_KEK_' . self::KEK_ID . '_B64', base64_encode(random_bytes(32)));
        $kms2 = LocalKms::fromEnv();
        
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unwrap failed');
        $kms2->unwrap(self::KEK_ID, $wrapped, self::STD_AAD);
    }

    public function testUnwrap_TamperedCiphertext_ThrowsRuntimeException(): void
    {
        $kms = LocalKms::fromEnv();
        $wrapped = $kms->wrap(self::KEK_ID, 'secret', self::STD_AAD);
        
        $raw = base64_decode($wrapped);
        $raw[strlen($raw) - 1] = $raw[strlen($raw) - 1] ^ "\x01"; // flip one bit
        $tampered = base64_encode($raw);
        
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unwrap failed');
        $kms->unwrap(self::KEK_ID, $tampered, self::STD_AAD);
    }

    public function testUnwrap_UnknownKekId_ThrowsRuntimeException(): void
    {
        $kms = LocalKms::fromEnv();
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unknown KEK id');
        $kms->unwrap('unknown-kek', 'dummy-data', self::STD_AAD);
    }

    /**
     * @covers \SecurePayload\KMS\LocalKms::wrap
     * @covers \SecurePayload\KMS\LocalKms::unwrap
     * SEC-08 Regression Test
     */
    public function testWrapUnwrap_ShuffledAad_Succeeds(): void
    {
        $kms = LocalKms::fromEnv();
        $plaintext = 'secret';
        
        $aadWrap = ['a' => 1, 'b' => 2];
        $aadUnwrap = ['b' => 2, 'a' => 1]; // Different order
        
        $wrapped = $kms->wrap(self::KEK_ID, $plaintext, $aadWrap);
        $unwrapped = $kms->unwrap(self::KEK_ID, $wrapped, $aadUnwrap);
        
        $this->assertSame($plaintext, $unwrapped, 'Unwrap should succeed despite different AAD key order due to ksort');
    }

    public function testWrapUnwrap_DifferentAadValues_Fails(): void
    {
        $kms = LocalKms::fromEnv();
        
        $wrapped = $kms->wrap(self::KEK_ID, 'secret', ['purpose' => 'test']);
        
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unwrap failed');
        $kms->unwrap(self::KEK_ID, $wrapped, ['purpose' => 'other']);
    }
}
