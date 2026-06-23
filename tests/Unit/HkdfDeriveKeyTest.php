<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\SecurePayload;

/**
 * Unit test untuk helper HKDF `SecurePayload::deriveKey()` (Phase 5).
 */
final class HkdfDeriveKeyTest extends TestCase
{
    private const MASTER = 'master-key-material-cukup-panjang-32+';

    public function testDeterministic(): void
    {
        $a = SecurePayload::deriveKey(self::MASTER, 'sp-sign-req');
        $b = SecurePayload::deriveKey(self::MASTER, 'sp-sign-req');
        $this->assertSame(bin2hex($a), bin2hex($b), 'Derivasi harus deterministik untuk input sama.');
    }

    public function testDefaultLengthIs32Bytes(): void
    {
        $this->assertSame(32, strlen(SecurePayload::deriveKey(self::MASTER, 'sp-aead-req')));
    }

    public function testCustomLength(): void
    {
        $this->assertSame(16, strlen(SecurePayload::deriveKey(self::MASTER, 'sp-aead-req', 16)));
        $this->assertSame(64, strlen(SecurePayload::deriveKey(self::MASTER, 'sp-aead-req', 64)));
    }

    public function testDomainSeparationByPurpose(): void
    {
        $sign = SecurePayload::deriveKey(self::MASTER, 'sp-sign-req');
        $aead = SecurePayload::deriveKey(self::MASTER, 'sp-aead-req');
        $resp = SecurePayload::deriveKey(self::MASTER, 'sp-aead-resp');
        $this->assertNotSame(bin2hex($sign), bin2hex($aead), 'Purpose berbeda harus menghasilkan subkey berbeda.');
        $this->assertNotSame(bin2hex($aead), bin2hex($resp));
        $this->assertNotSame(bin2hex($sign), bin2hex($resp));
    }

    public function testDifferentMasterDifferentKey(): void
    {
        $a = SecurePayload::deriveKey(self::MASTER, 'sp-sign-req');
        $b = SecurePayload::deriveKey(self::MASTER . 'x', 'sp-sign-req');
        $this->assertNotSame(bin2hex($a), bin2hex($b));
    }

    public function testEmptyMasterThrows(): void
    {
        $this->expectException(SecurePayloadException::class);
        SecurePayload::deriveKey('', 'sp-sign-req');
    }
}
