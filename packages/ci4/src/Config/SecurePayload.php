<?php
declare(strict_types=1);

namespace SecurePayload\Ci4\Config;

use CodeIgniter\Config\BaseConfig;

/**
 * Salin ke app/Config/SecurePayload.php dan sesuaikan env.
 */
class SecurePayload extends BaseConfig
{
    public string $mode = 'both';
    public string $version = \SecurePayload\SecurePayload::DEFAULT_VERSION;
    public string $signAlg = 'hmac';
    public bool $deriveKeys = false;
    /** @var list<string> */
    public array $bindHeaders = [];
    public int $replayTtl = 120;
    public int $clockSkew = 60;

    public string $serverKeyProvider = 'env';
    public string $keysTable = 'secure_keys';
    public bool $useKeyLifecycle = false;
    public bool $useEd25519 = false;
    public bool $useEd25519Server = false;

    public string $clientBaseUrl = '';
    public string $clientId = '';
    public string $keyId = '';
    public string $hmacSecret = '';
    public bool $hmacSecretIsHex = false;
    public string $aeadKeyB64 = '';
    public string $ed25519SecretB64 = '';
    public string $ed25519PublicServerB64 = '';

    /**
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        return [
            'mode' => $this->mode,
            'version' => $this->version,
            'sign_alg' => $this->signAlg,
            'derive_keys' => $this->deriveKeys,
            'bind_headers' => $this->bindHeaders,
            'replay_ttl' => $this->replayTtl,
            'clock_skew' => $this->clockSkew,
            'server' => [
                'key_provider' => $this->serverKeyProvider,
                'db' => [
                    'table' => $this->keysTable,
                    'use_key_lifecycle' => $this->useKeyLifecycle,
                    'use_ed25519' => $this->useEd25519,
                    'use_ed25519_server' => $this->useEd25519Server,
                ],
            ],
            'client' => [
                'base_url' => $this->clientBaseUrl,
                'client_id' => $this->clientId,
                'key_id' => $this->keyId,
                'hmac_secret' => $this->hmacSecret,
                'hmac_secret_is_hex' => $this->hmacSecretIsHex,
                'aead_key_b64' => $this->aeadKeyB64,
                'ed25519_secret_b64' => $this->ed25519SecretB64,
                'ed25519_public_server_b64' => $this->ed25519PublicServerB64,
            ],
            'replay_store' => ['driver' => 'file'],
        ];
    }
}
