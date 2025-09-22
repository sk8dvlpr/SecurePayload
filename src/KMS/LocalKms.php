<?php
declare(strict_types=1);

namespace SecurePayload\KMS;

use RuntimeException;

final class LocalKms implements Kms
{
    /** @var array<string,string> map kekId => raw 32-byte key */
    private array $keks;

    private function __construct(array $keksRawBytes)
    {
        $this->keks = $keksRawBytes;
    }

    public static function fromEnv(): self
    {
        $ids = array_filter(array_map('trim', explode(',', getenv('SECURE_KEKS') ?: '')));
        if (!$ids) throw new RuntimeException('No KEKs configured in .env (SECURE_KEKS)');
        $out = [];
        foreach ($ids as $id) {
            $envName = 'SECURE_KEK_' . $id . '_B64';
            $b64 = getenv($envName);
            if (!$b64) throw new RuntimeException("Missing $envName in .env");
            $raw = base64_decode($b64, true);
            if ($raw === false || strlen($raw) !== 32) throw new RuntimeException("$envName must be base64 of 32 bytes");
            $out[$id] = $raw;
        }
        return new self($out);
    }

    public function wrap(string $kekId, string $plaintext, array $aad): string
    {
        if (!extension_loaded('sodium')) throw new RuntimeException('libsodium extension required');
        $key = $this->keks[$kekId] ?? null;
        if ($key === null) throw new RuntimeException("Unknown KEK id: $kekId");

        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $aadStr = json_encode($aad, JSON_UNESCAPED_SLASHES);
        $ct = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, $aadStr, $nonce, $key);
        return base64_encode($nonce . $ct);
    }

    public function unwrap(string $kekId, string $blobB64, array $aad): string
    {
        if (!extension_loaded('sodium')) throw new RuntimeException('libsodium extension required');
        $key = $this->keks[$kekId] ?? null;
        if ($key === null) throw new RuntimeException("Unknown KEK id: $kekId");

        $raw = base64_decode($blobB64, true);
        if ($raw === false || strlen($raw) < 24) throw new RuntimeException('Wrapped blob corrupt');

        $nonce = substr($raw, 0, 24);
        $ct    = substr($raw, 24);
        $aadStr = json_encode($aad, JSON_UNESCAPED_SLASHES);
        $pt = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ct, $aadStr, $nonce, $key);
        if ($pt === false) throw new RuntimeException('Unwrap failed (bad AAD or key)');
        return $pt;
    }
}
