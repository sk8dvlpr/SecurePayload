<?php

declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\Delivery\Internal\LinkCodec;
use SecurePayload\Delivery\SecureLinkIssuer;
use SecurePayload\Delivery\SecureLinkVerifier;
use SecurePayload\Exceptions\SecurePayloadException;

/**
 * Unit test pasangan SecureLinkIssuer/SecureLinkVerifier (secure delivery):
 * format token, klaim, kanonik HMAC, matriks penolakan fail-closed beserta
 * urutannya, anti-replay single-use, binding dua arah, dan event audit.
 */
final class SecureLinkTest extends TestCase
{
    private const SECRET = 'unit-secret-0123456789abcdef-unit-secret';
    private const FILE_ID = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
    private const CLIENT = 'client_001';
    private const NOW = 1700000000;

    /** Waktu "sekarang" yang bisa digeser test (injeksi clock). */
    private int $now = self::NOW;

    /** @var list<array{0:string,1:array<string,mixed>}> Jejak semua event yang di-emit. */
    private array $events = [];

    /** Replay store in-memory sederhana: key sudah diklaim -> false. */
    private array $claimed = [];

    public function clock(): int
    {
        return $this->now;
    }

    /** fn(cacheKey, ttl): bool - true bila key belum pernah dipakai. */
    public function replayStore(string $cacheKey, int $ttl): bool
    {
        if (isset($this->claimed[$cacheKey])) {
            return false;
        }
        $this->claimed[$cacheKey] = true;
        return true;
    }

    private function issuer(): SecureLinkIssuer
    {
        return new SecureLinkIssuer(self::SECRET, ['clock' => [$this, 'clock']]);
    }

    private function verifier(): SecureLinkVerifier
    {
        return new SecureLinkVerifier(
            self::SECRET,
            [$this, 'replayStore'],
            ['clock' => [$this, 'clock'], 'onSecurityEvent' => function (string $event, array $ctx): void {
                $this->events[] = [$event, $ctx];
            }]
        );
    }

    /** Token valid standar untuk dipakai/pelintir oleh test. */
    private function validToken(bool $singleUse = true, ?string $boundTo = self::CLIENT): string
    {
        return $this->issuer()->issue(self::FILE_ID, 300, $singleUse, $boundTo);
    }

    private function eventNames(): array
    {
        return array_map(static fn (array $e): string => $e[0], $this->events);
    }

    // ------------------------------------------------------------------
    // SecureLinkIssuer
    // ------------------------------------------------------------------

    /** Pembanding segmen base64url - binary ketat (cermin LinkCodec::decodeB64Url). */
    private function b64UrlDecode(string $s): ?string
    {
        $this->assertSame(1, preg_match('/^[A-Za-z0-9_-]+$/', $s), "Segmen bukan base64url valid: $s");
        $std = strtr($s, '-_', '+/');
        $raw = base64_decode($std . str_repeat('=', (4 - strlen($std) % 4) % 4), true);
        return $raw === false ? null : $raw;
    }

    /** Urai token menjadi [payloadJson, sigBinary]. */
    private function unpackToken(string $token): array
    {
        $parts = explode('.', $token);
        $this->assertCount(3, $parts);
        $this->assertSame('sp1', $parts[0]);
        $payload = $this->b64UrlDecode($parts[1]);
        $sig = $this->b64UrlDecode($parts[2]);
        $this->assertNotNull($payload);
        $this->assertNotNull($sig);
        return [$payload, $sig];
    }

    public function testIssueMenghasilkanKlaimLengkapDanDeterministik(): void
    {
        $token = $this->issuer()->issue(self::FILE_ID, 300, true, self::CLIENT);
        [$payloadJson, $sig] = $this->unpackToken($token);

        $claims = json_decode($payloadJson, true);
        $this->assertSame(self::FILE_ID, $claims['file_id']);
        $this->assertSame(self::NOW + 300, $claims['exp']);
        $this->assertSame(self::NOW, $claims['iat']);
        $this->assertMatchesRegularExpression('/^[a-f0-9]{32}$/', $claims['jti']);
        $this->assertTrue($claims['su']);
        $this->assertSame(self::CLIENT, $claims['bound_to']);

        // Signature kanonik harus terverifikasi oleh LinkCodec::sign.
        $expected = LinkCodec::sign(LinkCodec::canonicalString($claims), self::SECRET);
        $this->assertSame($expected, $sig, 'Signature harus atas string kanonik, bukan byte JSON.');
    }

    public function testJtiUnikPerPemanggilan(): void
    {
        $a = $this->issuer()->issue('file_a', 60);
        $b = $this->issuer()->issue('file_a', 60);
        $this->assertNotSame($a, $b, 'Dua issue() identik tetap harus menghasilkan token beda (jti acak).');
    }

    public function testSingleUseFalseTercatatDiKlaim(): void
    {
        $token = $this->issuer()->issue('file_x', 60, false);
        [$payloadJson] = $this->unpackToken($token);
        $claims = json_decode($payloadJson, true);
        $this->assertFalse($claims['su']);
        $this->assertNull($claims['bound_to']);
    }

    public function testTtlDiLuarRentangDitolak(): void
    {
        $issuer = new SecureLinkIssuer(self::SECRET, ['clock' => [$this, 'clock'], 'ttlMax' => 600]);
        try {
            $issuer->issue('file_x', 0);
            $this->fail('ttl 0 harus ditolak.');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::BAD_REQUEST, $e->getCode());
        }
        try {
            $issuer->issue('file_x', 601);
            $this->fail('ttl di atas ttlMax harus ditolak.');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::BAD_REQUEST, $e->getCode());
        }
    }

    public function testFileIdDanBoundToBerbahayaDitolak(): void
    {
        $issuer = $this->issuer();
        // Whitespace/karakter kontrol bisa merusak string kanonik berbasis "\n".
        foreach (['', "dua\nbaris", 'ada spasi', "ada\ttab", "ctrl\x01"] as $bad) {
            try {
                $issuer->issue($bad, 60);
                $this->fail("fileId tidak aman harus ditolak: var_export($bad)");
            } catch (SecurePayloadException $e) {
                $this->assertSame(SecurePayloadException::BAD_REQUEST, $e->getCode());
            }
        }
        try {
            $issuer->issue('file_ok', 60, true, "bound\nto");
            $this->fail('boundTo tidak aman harus ditolak.');
        } catch (SecurePayloadException $e) {
            $this->assertSame(SecurePayloadException::BAD_REQUEST, $e->getCode());
        }
    }

    public function testIssuerSecretTerlaluPendekDitolak(): void
    {
        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionCode(SecurePayloadException::BAD_REQUEST);
        new SecureLinkIssuer('pendek');
    }

    // ------------------------------------------------------------------
    // SecureLinkVerifier — matriks penolakan
    // ------------------------------------------------------------------

    /** @return array<string,array{0:string}> */
    public static function providerTokenRusak(): array
    {
        $b64 = static fn (string $raw): string => rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
        return [
            'tanpa titik pemisah'  => ['bukan-token'],
            'empat segmen'         => ['sp1.a.b.c'],
            'prefix salah versi'   => ['sp9.YQ.YQ'],
            'segmen kosong'        => ['sp1..'],
            'base64 karakter liar' => ['sp1.a$b!c.YQ'],
            'payload bukan JSON'   => ['sp1.' . $b64('bukan json') . '.YQ'],
        ];
    }

    /**
     * @dataProvider providerTokenRusak
     */
    public function testFormatRusakDitolakFailClosed(string $token): void
    {
        $check = $this->verifier()->verify(self::FILE_ID, $token, null);
        $this->assertFalse($check['ok']);
        $this->assertSame(403, $check['status']);
        $this->assertSame('format_token', $check['error']);
        $this->assertContains('file_access_denied', $this->eventNames());
    }

    public function testSignaturePalsuDitolak(): void
    {
        $token = $this->validToken();
        $parts = explode('.', $token);
        $tampered = $parts[0] . '.' . $parts[1] . '.' . rtrim(strtr(base64_encode(str_repeat('x', 32)), '+/', '-_'), '=');
        $check = $this->verifier()->verify(self::FILE_ID, $tampered, null);
        $this->assertFalse($check['ok']);
        $this->assertSame('signature_invalid', $check['error']);
    }

    public function testFileMismatchDitolak(): void
    {
        $token = $this->validToken();
        $check = $this->verifier()->verify('file_lain_sama_sekali', $token, null);
        $this->assertFalse($check['ok']);
        $this->assertSame('file_mismatch', $check['error']);
    }

    public function testExpiredTolakPersisDiDetikExp(): void
    {
        $token = $this->validToken(); // exp = now + 300
        $v = $this->verifier();

        $this->now += 299; // masih berlaku
        $this->assertTrue($v->verify(self::FILE_ID, $token, self::CLIENT)['ok']);

        $this->now += 1; // persis exp -> kedaluwarsa
        $check = $v->verify(self::FILE_ID, $token, self::CLIENT);
        $this->assertFalse($check['ok']);
        $this->assertSame('token_expired', $check['error']);
    }

    public function testSingleUseTanpaReplayStoreDitolakFailClosed(): void
    {
        $v = new SecureLinkVerifier(self::SECRET, null, ['clock' => [$this, 'clock']]);
        $check = $v->verify(self::FILE_ID, $this->validToken(true, null), null);
        $this->assertFalse($check['ok']);
        $this->assertSame('replay_store_required', $check['error']);
    }

    public function testReuseDitolakOlehReplayStore(): void
    {
        $v = $this->verifier();
        $token = $this->validToken();

        $first = $v->verify(self::FILE_ID, $token, self::CLIENT);
        $this->assertTrue($first['ok']);
        $this->assertContains('file_accessed', $this->eventNames());

        $second = $v->verify(self::FILE_ID, $token, self::CLIENT);
        $this->assertFalse($second['ok']);
        $this->assertSame('token_reused', $second['error']);
    }

    public function testMultiUseTidakMenyentuhReplayStore(): void
    {
        $calls = 0;
        $v = new SecureLinkVerifier(self::SECRET, function (string $k, int $t) use (&$calls): bool {
            $calls++;
            return true;
        }, ['clock' => [$this, 'clock']]);
        $token = $this->validToken(false, null);

        $this->assertTrue($v->verify(self::FILE_ID, $token, null)['ok']);
        $this->assertTrue($v->verify(self::FILE_ID, $token, null)['ok']);
        $this->assertSame(0, $calls, 'Token multi-use tidak boleh menyentuh replayStore.');
    }

    // ------------------------------------------------------------------
    // SecureLinkVerifier — binding dua arah
    // ------------------------------------------------------------------

    public function testBoundTokenDenganHolderSalahDitolakTanpaMembakarToken(): void
    {
        $v = $this->verifier();
        $token = $this->validToken(true, self::CLIENT);

        // Dua percobaan dengan holder salah: harus binding_mismatch, dan
        // jti TIDAK boleh terbakar (pemegang sah masih bisa lolos).
        $r1 = $v->verify(self::FILE_ID, $token, 'client_lain');
        $r2 = $v->verify(self::FILE_ID, $token, null);
        $this->assertSame('binding_mismatch', $r1['error']);
        $this->assertSame('binding_mismatch', $r2['error']);

        $ok = $v->verify(self::FILE_ID, $token, self::CLIENT);
        $this->assertTrue($ok['ok'], 'Pemegang sah harus tetap lolos setelah penolakan binding.');
    }

    public function testUnboundTokenDenganParamBoundToDitolak(): void
    {
        $v = $this->verifier();
        $token = $this->validToken(true, null);
        $check = $v->verify(self::FILE_ID, $token, self::CLIENT);
        $this->assertFalse($check['ok']);
        $this->assertSame('binding_mismatch', $check['error'], 'Link tak terikat tidak boleh diklaim terikat.');
    }

    public function testBindingCocokMengembalikanKlaimLengkap(): void
    {
        $check = $this->verifier()->verify(self::FILE_ID, $this->validToken(true, self::CLIENT), self::CLIENT);
        $this->assertTrue($check['ok']);
        $this->assertSame(200, $check['status']);
        $this->assertSame(self::FILE_ID, $check['claims']['file_id']);
        $this->assertSame(self::CLIENT, $check['claims']['bound_to']);
        $this->assertTrue($check['claims']['su']);
        $this->assertArrayHasKey('jti', $check['claims']);
        $this->assertContains('file_accessed', $this->eventNames());
        $this->assertNotContains('file_access_denied', $this->eventNames());
    }

    // ------------------------------------------------------------------
    // SecureLinkVerifier — event audit & konstruksi
    // ------------------------------------------------------------------

    public function testSetiapPenolakanEmitSatuEventDenied(): void
    {
        $v = $this->verifier();
        $v->verify(self::FILE_ID, 'rusak-total', null);     // format_token
        $v->verify('file_beda', $this->validToken(), null); // file_mismatch
        $denied = array_values(array_filter($this->eventNames(), fn (string $e): bool => $e === 'file_access_denied'));
        $this->assertCount(2, $denied, 'Setiap penolakan tepat satu event file_access_denied.');
    }

    public function testVerifierSecretTerlaluPendekDitolak(): void
    {
        $this->expectException(SecurePayloadException::class);
        $this->expectExceptionCode(SecurePayloadException::BAD_REQUEST);
        new SecureLinkVerifier('pendek');
    }
}
