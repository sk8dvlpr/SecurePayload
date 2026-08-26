<?php
declare(strict_types=1);

namespace SecurePayload\Exceptions;

use RuntimeException;

/**
 * Dilempar saat operasi decrypt arsip menemui kunci berstatus `destroyed`
 * ({@see \SecurePayload\KMS\KeyStatus::DESTROYED}).
 *
 * Sengaja STANDALONE (bukan turunan SecurePayloadException yang final) agar
 * aplikasi dapat menangkap exception ini secara terpisah — misalnya untuk
 * memetakan ke HTTP 410 Gone tanpa menangkap error SecurePayload lain.
 */
final class KeyDestroyedException extends RuntimeException
{
    private array $context = [];

    public function __construct(string $message = '', int $code = 410, array $context = [])
    {
        parent::__construct($message, $code);
        $this->context = $context;
    }

    /**
     * Context non-secret tambahan (mis. clientId/keyId) saat exception dilempar.
     *
     * @return array<string,mixed>
     */
    public function getContext(): array
    {
        return $this->context;
    }
}
