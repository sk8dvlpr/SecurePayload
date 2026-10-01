<?php
declare(strict_types=1);

namespace SecurePayload\KMS;

use SecurePayload\Exceptions\SecurePayloadException;

/**
 * Penyedia kunci dari environment variable.
 *
 * Format env: SECUREPAYLOAD_{CLIENTID}_{KEYID}_HMAC_SECRET (dst).
 * clientId/keyId WAJIB cocok dengan /^[A-Za-z0-9_]+$/ — karakter lain
 * (termasuk `-` dan `.`) ditolak agar normalisasi tidak menabrak identitas
 * berbeda (mis. client-a vs client_a).
 */
final class EnvKeyProvider implements SecureKeyProvider
{
    public function load(string $clientId, string $keyId): array
    {
        if (!$this->isSafeId($clientId) || !$this->isSafeId($keyId)) {
            throw new SecurePayloadException(
                'clientId/keyId EnvKeyProvider hanya boleh [A-Za-z0-9_] (tolak normalisasi yang menabrak identitas)',
                SecurePayloadException::BAD_REQUEST,
                ['clientId' => $clientId, 'keyId' => $keyId]
            );
        }

        $cid = strtoupper($clientId);
        $kid = strtoupper($keyId);

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

    private function isSafeId(string $id): bool
    {
        return $id !== '' && (bool) preg_match('/^[A-Za-z0-9_]+$/', $id);
    }
}
