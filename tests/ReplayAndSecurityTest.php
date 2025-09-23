<?php
declare(strict_types=1);

namespace SecurePayload\Tests;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

/**
 * Extra security tests: replay, timestamp rage, nonce/digest/signature errors.
 */
final class ReplayAndSecurityTest extends TestCase
{
    public function testReplayDetectionWithCustomStore(): void
    {
        $spClient = new SecurePayload([
            'mode'         => 'hmac',
            'version'      => '1',
            'clientId'     => 'c2',
            'keyId'        => 'k2',
            'hmacSecretRaw'=> 'secret2',
        ]);

        [$headers, $body] = $spClient->buildHeadersAndBody('https://api.example.com/replay?x=9', 'POST', ['r'=>1]);

        // Custom replayStore: return true only the first time a cacheKey is seen
        $seen = [];
        $replayStore = function(string $cacheKey, int $ttl) use (&$seen): bool {
            if (isset($seen[$cacheKey])) return false;
            $seen[$cacheKey] = time();
            return true;
        };

        $spServer = new SecurePayload([
            'mode'        => 'hmac',
            'version'     => '1',
            'keyLoader'   => fn(string $cid, string $kid) => ['hmacSecret'=>'secret2','aeadKeyB64'=>null],
            'replayStore' => $replayStore,
            'replayTtl'   => 120,
            'clockSkew'   => 60,
        ]);

        $vr1 = $spServer->verifySimple($headers, $body);
        $this->assertTrue($vr1['ok'] ?? false, json_encode($vr1));

        // Re-use exact same headers/body (same ts+nonce) should be rejected
        $vr2 = $spServer->verifySimple($headers, $body);
        $this->assertFalse($vr2['ok'] ?? true);
        $this->assertSame(401, $vr2['status'] ?? 0);
        $this->assertStringContainsString('Replay', $vr2['error'] ?? '');
    }

    public function testTimestampOutOfRangeOnServerHmac(): void
    {
        $spClient = new SecurePayload([
            'mode'         => 'hmac',
            'version'      => '1',
            'clientId'     => 'c3',
            'keyId'        => 'k3',
            'hmacSecretRaw'=> 'secret3',
        ]);

        [$headers, $body] = $spClient->buildHeadersAndBody('https://api.example.com/hmac?y=1', 'POST', ['t'=>1]);

        // Parse canonical header for method/path/query to recompute signature
        $parts = explode("\n", $headers[SecurePayload::HX_CANON_REQ], 3);
        [$method, $path, $qStr] = $parts;

        // Tamper timestamp to far past and recompute signature accordingly
        $oldTs = (string) (time() - 999999);
        $headers[SecurePayload::HX_TIMESTAMP] = $oldTs;

        $digestHeader = $headers[SecurePayload::HX_BODY_DIGEST];
        $digestB64 = substr($digestHeader, 7); // remove "sha256="
        $msg = SecurePayload::hmacMessage('1', 'c3', 'k3', $oldTs, $headers[SecurePayload::HX_NONCE], $method, $path, $qStr, $digestB64);
        $headers[SecurePayload::HX_SIGNATURE] = base64_encode(hash_hmac('sha256', $msg, 'secret3', true));

        $spServer = new SecurePayload([
            'mode'        => 'hmac',
            'version'     => '1',
            'keyLoader'   => fn(string $cid, string $kid) => ['hmacSecret'=>'secret3','aeadKeyB64'=>null],
            'replayTtl'   => 60,   // tight window
            'clockSkew'   => 0,
        ]);

        $vr = $spServer->verifySimple($headers, $body);
        $this->assertFalse($vr['ok'] ?? true);
        $this->assertSame(401, $vr['status'] ?? 0);
        $this->assertStringContainsString('Timestamp', $vr['error'] ?? '');
    }

    public function testAeadNonceMismatchInBoth(): void
    {
        if (!\extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium is required');
        }

        $aeadKey = base64_encode(random_bytes(32));

        $spClient = new SecurePayload([
            'mode'         => 'both',
            'version'      => '1',
            'clientId'     => 'c4',
            'keyId'        => 'k4',
            'hmacSecretRaw'=> 'secret4',
            'aeadKeyB64'   => $aeadKey,
        ]);

        [$headers, $body] = $spClient->buildHeadersAndBody('https://api.example.com/nonce?z=9', 'POST', ['n'=>1]);

        // Tamper X-Canonical-Request path -> will make server calculate different AEAD nonce
        $parts = explode("\n", $headers[SecurePayload::HX_CANON_REQ], 3);
        $headers[SecurePayload::HX_CANON_REQ] = $parts[0] . "\n" . "/tampered" . "\n" . $parts[2];

        $spServer = new SecurePayload([
            'mode'      => 'both',
            'version'   => '1',
            'keyLoader' => fn(string $cid, string $kid) => ['hmacSecret'=>'secret4','aeadKeyB64'=>$aeadKey],
        ]);

        $vr = $spServer->verifySimple($headers, $body);
        $this->assertFalse($vr['ok'] ?? true);
        $this->assertSame(401, $vr['status'] ?? 0);
        $this->assertStringContainsString('AEAD nonce mismatch', $vr['error'] ?? '');
    }

    public function testHmacBodyDigestMismatch(): void
    {
        $spClient = new SecurePayload([
            'mode'         => 'hmac',
            'version'      => '1',
            'clientId'     => 'c5',
            'keyId'        => 'k5',
            'hmacSecretRaw'=> 'secret5',
        ]);

        [$headers, $body] = $spClient->buildHeadersAndBody('https://api.example.com/digest?d=1', 'POST', ['a'=>1]);

        // Tamper body but keep headers unchanged
        $tamperedBody = json_encode(['a'=>2]);

        $spServer = new SecurePayload([
            'mode'      => 'hmac',
            'version'   => '1',
            'keyLoader' => fn(string $cid, string $kid) => ['hmacSecret'=>'secret5','aeadKeyB64'=>null],
        ]);

        $vr = $spServer->verifySimple($headers, $tamperedBody);
        $this->assertFalse($vr['ok'] ?? true);
        $this->assertSame(422, $vr['status'] ?? 0);
        $this->assertStringContainsString('Body digest mismatch', $vr['error'] ?? '');
    }

    public function testHmacSignatureMismatch(): void
    {
        $spClient = new SecurePayload([
            'mode'         => 'hmac',
            'version'      => '1',
            'clientId'     => 'c6',
            'keyId'        => 'k6',
            'hmacSecretRaw'=> 'secret6',
        ]);

        [$headers, $body] = $spClient->buildHeadersAndBody('https://api.example.com/sig', 'POST', ['s'=>1]);

        // Tamper signature
        $headers[SecurePayload::HX_SIGNATURE] = base64_encode(random_bytes(32));

        $spServer = new SecurePayload([
            'mode'      => 'hmac',
            'version'   => '1',
            'keyLoader' => fn(string $cid, string $kid) => ['hmacSecret'=>'secret6','aeadKeyB64'=>null],
        ]);

        $vr = $spServer->verifySimple($headers, $body);
        $this->assertFalse($vr['ok'] ?? true);
        $this->assertSame(401, $vr['status'] ?? 0);
        $this->assertStringContainsString('Signature mismatch', $vr['error'] ?? '');
    }
}
