<?php

declare(strict_types=1);

namespace SecurePayload\Internal;

/**
 * Emitter event keamanan minimalis untuk penggunaan internal.
 *
 * Semantik identik `SecurePayloadConfig::emitEvent()`: murni observasional.
 * Exception apa pun dari handler ditelan agar tidak pernah mengubah hasil/
 * keamanan alur utama. PERINGATAN: pemanggil WAJIB hanya mengisi $context
 * dengan data non-secret (clientId/keyId/alasan/timestamp) — tidak pernah
 * secret, plaintext, atau ciphertext.
 */
final class EventEmitter
{
    /** @var callable|null Handler event; null berarti no-op */
    private $handler;

    /**
     * @param callable|null $handler Callback dengan signature (string $event, array $context)
     */
    public function __construct(?callable $handler)
    {
        $this->handler = $handler;
    }

    /**
     * Emit satu event ke handler bila terpasang. Telan semua \Throwable dari
     * handler — observability tidak boleh mengganggu alur utama.
     *
     * @param array<string,mixed> $context WAJIB non-secret
     */
    public function emit(string $event, array $context = []): void
    {
        if ($this->handler === null) {
            return;
        }
        try {
            call_user_func($this->handler, $event, $context);
        } catch (\Throwable $e) {
            // Sengaja diabaikan: observability tidak boleh mengganggu alur utama.
        }
    }
}
