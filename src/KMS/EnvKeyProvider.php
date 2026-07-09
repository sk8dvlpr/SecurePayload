<?php
declare(strict_types=1);

namespace SecurePayload\KMS;

final class EnvKeyProvider implements SecureKeyProvider
{
    public function load(string $clientId, string $keyId): array
    {
        $cid = strtoupper(preg_replace('/[^A-Za-z0-9_]/','_', $clientId));
        $kid = strtoupper(preg_replace('/[^A-Za-z0-9_]/','_', $keyId));

        $hmac = getenv("SECUREPAYLOAD_{$cid}_{$kid}_HMAC_SECRET");
        $aead = getenv("SECUREPAYLOAD_{$cid}_{$kid}_AEAD_KEY_B64");
        $ed25519Pub = getenv("SECUREPAYLOAD_{$cid}_{$kid}_ED25519_PUBLIC_B64");
        $ed25519ServerSecret = getenv("SECUREPAYLOAD_{$cid}_{$kid}_ED25519_SERVER_SECRET_B64");
        $ed25519ServerPub = getenv("SECUREPAYLOAD_{$cid}_{$kid}_ED25519_SERVER_PUBLIC_B64");

        return [
            'hmacSecret' => $hmac !== false && $hmac !== '' ? (string)$hmac : null,
            'aeadKeyB64' => $aead !== false && $aead !== '' ? (string)$aead : null,
            'ed25519PublicKeyB64' => $ed25519Pub !== false && $ed25519Pub !== '' ? (string)$ed25519Pub : null,
            'ed25519SecretKeyServerB64' => $ed25519ServerSecret !== false && $ed25519ServerSecret !== '' ? (string)$ed25519ServerSecret : null,
            'ed25519PublicKeyServerB64' => $ed25519ServerPub !== false && $ed25519ServerPub !== '' ? (string)$ed25519ServerPub : null,
        ];
    }
}
