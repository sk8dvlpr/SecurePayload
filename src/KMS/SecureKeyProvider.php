<?php
declare(strict_types=1);

namespace SecurePayload\KMS;

interface SecureKeyProvider
{
    /** @return array{hmacSecret:?string,aeadKeyB64:?string} */
    public function load(string $clientId, string $keyId): array;
}
