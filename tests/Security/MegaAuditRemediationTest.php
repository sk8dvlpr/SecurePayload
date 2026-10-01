<?php

declare(strict_types=1);

namespace SecurePayload\Tests\Security;

use PHPUnit\Framework\TestCase;
use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\File\FileValidation;
use SecurePayload\KMS\EnvKeyProvider;
use SecurePayload\SecurePayload;

final class MegaAuditRemediationTest extends TestCase
{
    private string $hmac;
    private string $aeadB64;

    protected function setUp(): void
    {
        $this->hmac = str_repeat('a', 32);
        $this->aeadB64 = base64_encode(random_bytes(32));
    }

    private function client(string $mode = 'hmac'): SecurePayload
    {
        return new SecurePayload([
            'mode' => $mode,
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => $this->hmac,
            'aeadKeyB64' => $this->aeadB64,
        ]);
    }

    private function server(string $mode = 'hmac', array $extra = []): SecurePayload
    {
        return new SecurePayload(array_merge([
            'mode' => $mode,
            'hmacSecretRaw' => $this->hmac,
            'aeadKeyB64' => $this->aeadB64,
            'keyLoader' => fn (): array => [
                'hmacSecret' => $this->hmac,
                'aeadKeyB64' => $this->aeadB64,
            ],
        ], $extra));
    }

    public function testInvalidSignatureDoesNotBurnNonce(): void
    {
        $seen = [];
        $store = static function (string $key, int $ttl) use (&$seen): bool {
            if (isset($seen[$key])) {
                return false;
            }
            $seen[$key] = true;
            return true;
        };

        $client = $this->client('hmac');
        [$h, $b] = $client->buildHeadersAndBody('https://ex.test/api?x=1', 'POST', ['ok' => true]);

        $server = $this->server('hmac', ['replayStore' => $store]);
        $bad = $h;
        $bad['X-Signature'] = base64_encode(str_repeat("\0", 32));

        $res = $server->verify($bad, $b, 'POST', '/api', ['x' => '1']);
        $this->assertFalse($res['ok']);
        $this->assertSame([], $seen);

        $ok = $server->verify($h, $b, 'POST', '/api', ['x' => '1']);
        $this->assertTrue($ok['ok']);
        $this->assertCount(1, $seen);
    }

    public function testRequireReplayStoreWithoutStoreThrowsAtConstruct(): void
    {
        $this->expectException(SecurePayloadException::class);
        new SecurePayload([
            'mode' => 'hmac',
            'hmacSecretRaw' => $this->hmac,
            'requireReplayStore' => true,
        ]);
    }

    public function testEnvKeyProviderRejectsHyphenCollisionIds(): void
    {
        $p = new EnvKeyProvider();
        $this->expectException(SecurePayloadException::class);
        $p->load('client-a', 'key_1');
    }

    public function testVerifyFilePayloadHonorsQuery(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'spf');
        $this->assertNotFalse($tmp);
        file_put_contents($tmp, 'hello-file');
        $renamed = $tmp . '.txt';
        rename($tmp, $renamed);

        try {
            $client = $this->client('hmac');
            [$h, $b] = $client->buildFilePayload('https://ex.test/upload?tok=abc', 'POST', $renamed);

            $server = $this->server('hmac');
            $fail = $server->verifyFilePayload($h, $b, 'POST', '/upload', [], []);
            $this->assertFalse($fail['ok']);

            $ok = $server->verifyFilePayload($h, $b, 'POST', '/upload', [], ['tok' => 'abc']);
            $this->assertTrue($ok['ok']);
            $this->assertSame('hello-file', $ok['file']['content_decoded']);
        } finally {
            @unlink($renamed);
        }
    }

    public function testMaxSizeRejectsOversizedBase64BeforeIntegrity(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'spf');
        $this->assertNotFalse($tmp);
        file_put_contents($tmp, str_repeat('Z', 100));
        $renamed = $tmp . '.txt';
        rename($tmp, $renamed);

        try {
            $client = $this->client('hmac');
            [$h, $b] = $client->buildFilePayload('https://ex.test/up', 'POST', $renamed);
            $json = json_decode($b, true);
            $json['_attachment']['size'] = 1;
            [$h2, $b2] = $client->buildHeadersAndBody('https://ex.test/up', 'POST', $json);

            $server = $this->server('hmac');
            $res = $server->verifyFilePayload($h2, $b2, 'POST', '/up', ['max_size' => 10]);
            $this->assertFalse($res['ok']);
            $this->assertSame(413, $res['status']);
        } finally {
            @unlink($renamed);
        }
    }

    public function testSanitizeFileNameBlocksReservedAndNul(): void
    {
        $this->assertSame('unnamed', FileValidation::sanitizeFileName(''));
        $this->assertStringStartsWith('_', FileValidation::sanitizeFileName('CON.txt'));
        $this->assertSame('safe.txt', FileValidation::sanitizeFileName('a/b/' . chr(0) . 'safe.txt'));
    }
}
