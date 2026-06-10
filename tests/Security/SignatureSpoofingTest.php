<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Security;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;

final class SignatureSpoofingTest extends TestCase
{
    private const HMAC_32 = 'test-hmac-secret-must-be-32bytes!!';
    private const CLIENT_ID = 'attacker';
    private const KEY_ID = 'key1';

    private function makeServer(): SecurePayload
    {
        return new SecurePayload([
            'mode' => 'hmac',
            'version' => '1',
            'keyLoader' => fn($c, $k) => ['hmacSecret' => self::HMAC_32, 'aeadKeyB64' => null]
        ]);
    }

    private function createInnocentRequestHeaders(string $innocentMethod, string $innocentPath, string $bodyJson): array
    {
        $ts = (string) time();
        $nonce = SecurePayload::genNonceB64();
        $digest = 'sha256=' . SecurePayload::bodyDigestB64($bodyJson);

        $canonicalHeaderContent = base64_encode(implode("\n", [$innocentMethod, $innocentPath, '']));

        $msgKey = implode("\n", [
            '1',
            "c=" . self::CLIENT_ID,
            "k=" . self::KEY_ID,
            "t=$ts",
            "n=$nonce",
            "m=$innocentMethod",
            "p=$innocentPath",
            "q=",
            "bd=$digest",
            ""
        ]);
        
        // Use the exact hmacMessage format from SecurePayload
        $msg = SecurePayload::hmacMessage(
            '1', self::CLIENT_ID, self::KEY_ID, $ts, $nonce, 
            $innocentMethod, $innocentPath, '', base64_encode(hash('sha256', $bodyJson, true))
        );

        $signature = base64_encode(hash_hmac('sha256', $msg, self::HMAC_32, true));

        return [
            'X-Client-Id' => self::CLIENT_ID,
            'X-Key-Id' => self::KEY_ID,
            'X-Timestamp' => $ts,
            'X-Nonce' => $nonce,
            'X-Signature-Version' => '1',
            'X-Signature-Algorithm' => 'HMAC-SHA256',
            'X-Signature' => $signature,
            'X-Body-Digest' => $digest,
            'X-Canonical-Request' => $canonicalHeaderContent
        ];
    }

    public function testValidRequestToCorrectEndpointSucceeds(): void
    {
        $server = $this->makeServer();
        $bodyJson = json_encode(['data' => 'nothing suspicious']);
        
        $headers = $this->createInnocentRequestHeaders('GET', '/public/info', $bodyJson);
        
        $result = $server->verifySimple($headers, $bodyJson, 'GET', '/public/info');
        
        $this->assertTrue($result['ok']);
    }

    public function testServerIgnoresXCanonicalRequestSpoofing(): void
    {
        $server = $this->makeServer();
        $bodyJson = json_encode(['data' => 'nothing suspicious']);
        
        // Attacker creates a valid signature for GET /public/info
        $headers = $this->createInnocentRequestHeaders('GET', '/public/info', $bodyJson);
        
        // Attacker sends the request to POST /admin/delete-user
        // The server should use the actual request method and path, ignoring the canonical header
        $actualMethod = 'POST';
        $actualPath = '/admin/delete-user';
        
        $result = $server->verifySimple($headers, $bodyJson, $actualMethod, $actualPath);
        
        $this->assertFalse($result['ok'], 'Security bypass successful! Server accepted spoofed request.');
        $this->assertSame(401, $result['status']);
        $this->assertStringContainsString('Tanda Tangan (Signature) tidak valid', $result['error']);
    }

    public function testTamperedCanonicalHeaderDoesNotBypassSignatureCheck(): void
    {
        $server = $this->makeServer();
        $bodyJson = json_encode(['data' => 'nothing suspicious']);
        
        $headers = $this->createInnocentRequestHeaders('GET', '/public/info', $bodyJson);
        
        // Attacker modifies the canonical header to match the target endpoint
        $headers['X-Canonical-Request'] = base64_encode(implode("\n", ['POST', '/admin/delete-user', '']));
        
        // Attacker sends the request to POST /admin/delete-user
        $result = $server->verifySimple($headers, $bodyJson, 'POST', '/admin/delete-user');
        
        $this->assertFalse($result['ok'], 'Tampering canonical header should still fail signature verification.');
        $this->assertSame(401, $result['status']);
        $this->assertStringContainsString('Tanda Tangan (Signature) tidak valid', $result['error']);
    }
}
