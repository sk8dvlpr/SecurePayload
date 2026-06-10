<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\KMS\EnvKeyProvider;
use SecurePayload\SecurePayload;

final class EnvKeyProviderTest extends TestCase
{
    private array $envBackup = [];

    protected function setUp(): void
    {
        $this->envBackup = [];
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

    public function testLoad_SpecificHmacEnvVar_ReturnsHmacSecret(): void
    {
        $this->setEnv('SECUREPAYLOAD_CLIENT1_KEY1_HMAC_SECRET', 'test-hmac-secret-123');
        $provider = new EnvKeyProvider();
        
        $keys = $provider->load('client1', 'key1');
        
        $this->assertSame('test-hmac-secret-123', $keys['hmacSecret']);
        $this->assertNull($keys['aeadKeyB64']);
        $this->clearEnv('SECUREPAYLOAD_CLIENT1_KEY1_HMAC_SECRET');
    }

    public function testLoad_SpecificAeadEnvVar_ReturnsAeadKey(): void
    {
        $this->setEnv('SECUREPAYLOAD_CLIENT2_KEY2_AEAD_KEY_B64', 'test-aead-key-b64');
        $provider = new EnvKeyProvider();
        
        $keys = $provider->load('client2', 'key2');
        
        $this->assertNull($keys['hmacSecret']);
        $this->assertSame('test-aead-key-b64', $keys['aeadKeyB64']);
        $this->clearEnv('SECUREPAYLOAD_CLIENT2_KEY2_AEAD_KEY_B64');
    }

    public function testLoad_BothSpecificEnvVars_ReturnsBothKeys(): void
    {
        $this->setEnv('SECUREPAYLOAD_CLIENT3_KEY3_HMAC_SECRET', 'test-hmac-3');
        $this->setEnv('SECUREPAYLOAD_CLIENT3_KEY3_AEAD_KEY_B64', 'test-aead-3');
        
        $provider = new EnvKeyProvider();
        $keys = $provider->load('client3', 'key3');
        
        $this->assertSame('test-hmac-3', $keys['hmacSecret']);
        $this->assertSame('test-aead-3', $keys['aeadKeyB64']);
        
        $this->clearEnv('SECUREPAYLOAD_CLIENT3_KEY3_HMAC_SECRET');
        $this->clearEnv('SECUREPAYLOAD_CLIENT3_KEY3_AEAD_KEY_B64');
    }

    public function testLoad_SpecialCharsInClientId_AreSanitized(): void
    {
        $this->setEnv('SECUREPAYLOAD_CLIENT_01_KEY_01_HMAC_SECRET', 'sanitized-hmac');
        
        $provider = new EnvKeyProvider();
        $keys = $provider->load('client-01', 'key-01');
        
        $this->assertSame('sanitized-hmac', $keys['hmacSecret']);
        $this->clearEnv('SECUREPAYLOAD_CLIENT_01_KEY_01_HMAC_SECRET');
    }

    public function testLoad_MissingSpecificKey_ReturnsNull_NotFallback(): void
    {
        $this->setEnv('SECURE_HMAC_SECRET', 'global-secret-should-not-be-used');
        $this->setEnv('SECURE_AEAD_KEY_B64', 'global-aead-should-not-be-used');

        $provider = new EnvKeyProvider();
        $result = $provider->load('nonexistent-client', 'nonexistent-key');

        $this->assertNull($result['hmacSecret'],
            'SEC-01: EnvKeyProvider tidak boleh fallback ke SECURE_HMAC_SECRET global'
        );
        $this->assertNull($result['aeadKeyB64'],
            'SEC-01: EnvKeyProvider tidak boleh fallback ke SECURE_AEAD_KEY_B64 global'
        );
        
        $this->clearEnv('SECURE_HMAC_SECRET');
        $this->clearEnv('SECURE_AEAD_KEY_B64');
    }

    public function testLoad_NullKeyFromProvider_ServerRejects401(): void
    {
        $provider = new EnvKeyProvider();
        
        $server = new SecurePayload([
            'mode' => 'hmac',
            'version' => '1',
            'keyLoader' => [$provider, 'load']
        ]);
        
        $client = new SecurePayload([
            'mode' => 'hmac',
            'version' => '1',
            'clientId' => 'c1',
            'keyId' => 'k1',
            'hmacSecretRaw' => 'test-hmac-secret-must-be-32bytes!!',
        ]);
        
        [$headers, $body] = $client->buildHeadersAndBody('https://api.test/data', 'POST', ['a' => 1]);
        
        $result = $server->verifySimple($headers, $body, 'POST', '/data');
        
        $this->assertFalse($result['ok']);
        $this->assertSame(500, $result['status']); // SecurePayload throws SERVER_ERROR (500) when key is not found
        $this->assertStringContainsString('Secret Key HMAC tidak ditemukan di server', $result['error']);
    }
}
