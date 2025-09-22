<?php
declare(strict_types=1);

namespace SecurePayload\KMS;

interface Kms {
    public function wrap(string $kekId, string $plaintext, array $aad): string;
    public function unwrap(string $kekId, string $blobB64, array $aad): string;
}
