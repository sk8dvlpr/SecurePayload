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

        if (!$hmac && !$aead) {
            $hmac = getenv("SECURE_HMAC_SECRET") ?: null;
            $aead = getenv("SECURE_AEAD_KEY_B64") ?: null;
        }

        return [
            'hmacSecret' => $hmac !== false && $hmac !== '' ? (string)$hmac : null,
            'aeadKeyB64' => $aead !== false && $aead !== '' ? (string)$aead : null,
        ];
    }
}
