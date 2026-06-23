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

        return [
            'hmacSecret' => $hmac !== false && $hmac !== '' ? (string)$hmac : null,
            'aeadKeyB64' => $aead !== false && $aead !== '' ? (string)$aead : null,
            'ed25519PublicKeyB64' => $ed25519Pub !== false && $ed25519Pub !== '' ? (string)$ed25519Pub : null,
        ];
    }
}
