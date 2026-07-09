<?php

declare(strict_types=1);

namespace SecurePayload\Observability;

use SecurePayload\SecurePayload;

/**
 * Exporter span OpenTelemetry untuk event keamanan SecurePayload (Phase 17).
 *
 * Kompatibel dengan `open-telemetry/sdk` via duck typing pada objek tracer
 * (metode `spanBuilder(string)` → builder dengan `startSpan()`).
 * Tanpa tracer, callback menjadi no-op aman.
 *
 * Context span TIDAK pernah memuat secret/plaintext/ciphertext.
 */
final class OpenTelemetrySecurityExporter
{
    /** @var object|null Tracer compatible OpenTelemetry (TracerInterface) */
    private $tracer;

    private bool $includeClientId;
    private bool $includeKeyId;
    private string $spanName;

    /**
     * @param array<string,mixed> $opts
     *   - tracer: object|null Tracer OpenTelemetry (opsional)
     *   - includeClientId: bool (default false)
     *   - includeKeyId: bool (default false)
     *   - spanName: string (default 'securepayload.security_event')
     */
    public function __construct(array $opts = [])
    {
        $tracer = $opts['tracer'] ?? null;
        $this->tracer = is_object($tracer) ? $tracer : null;
        $this->includeClientId = !empty($opts['includeClientId']);
        $this->includeKeyId = !empty($opts['includeKeyId']);
        $name = $opts['spanName'] ?? 'securepayload.security_event';
        $this->spanName = is_string($name) && $name !== '' ? $name : 'securepayload.security_event';
    }

    /**
     * Factory callback untuk opsi `onSecurityEvent` di SecurePayload.
     *
     * @return callable(string, array<string,mixed>): void
     */
    public function onSecurityEvent(): callable
    {
        return function (string $event, array $context): void {
            try {
                $this->record($event, $context);
            } catch (\Throwable $e) {
                // Observability tidak boleh memengaruhi verifikasi.
            }
        };
    }

    /**
     * Mulai span verifikasi manual (opsional, untuk lapisan aplikasi).
     *
     * @return object|null Handle span; pass ke {@see endVerifySpan()}
     */
    public function startVerifySpan(string $operation = 'securepayload.verify'): ?object
    {
        if ($this->tracer === null) {
            return null;
        }

        try {
            $builder = $this->tracer->spanBuilder($operation);
            if (!is_object($builder) || !method_exists($builder, 'startSpan')) {
                return null;
            }
            $span = $builder->startSpan();
            return is_object($span) ? $span : null;
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * Akhiri span verifikasi manual.
     */
    public function endVerifySpan(?object $span, bool $ok): void
    {
        if ($span === null) {
            return;
        }

        try {
            if (!$ok && method_exists($span, 'setStatus')) {
                $statusClass = 'OpenTelemetry\\API\\Trace\\StatusCode';
                if (class_exists($statusClass) && defined($statusClass . '::STATUS_ERROR')) {
                    $span->setStatus(constant($statusClass . '::STATUS_ERROR'));
                }
            }
            if (method_exists($span, 'end')) {
                $span->end();
            }
        } catch (\Throwable $e) {
            // Abaikan.
        }
    }

    /**
     * Catat satu event keamanan sebagai span (aman untuk testing langsung).
     *
     * @param array<string,mixed> $context
     */
    public function record(string $event, array $context): void
    {
        if ($this->tracer === null) {
            return;
        }

        $span = null;
        try {
            $builder = $this->tracer->spanBuilder($this->spanName);
            if (!is_object($builder) || !method_exists($builder, 'startSpan')) {
                return;
            }
            $span = $builder->startSpan();
            if (!is_object($span)) {
                return;
            }

            if (method_exists($span, 'setAttribute')) {
                $span->setAttribute('securepayload.event', $event);
                if ($this->includeClientId && isset($context['clientId'])) {
                    $span->setAttribute('securepayload.client_id', (string) $context['clientId']);
                }
                if ($this->includeKeyId && isset($context['keyId'])) {
                    $span->setAttribute('securepayload.key_id', (string) $context['keyId']);
                }
                foreach (['scope', 'source', 'alg', 'kind'] as $extra) {
                    if (isset($context[$extra])) {
                        $span->setAttribute('securepayload.' . $extra, (string) $context[$extra]);
                    }
                }
            }

            if (method_exists($span, 'setStatus')) {
                $statusClass = 'OpenTelemetry\\API\\Trace\\StatusCode';
                if (class_exists($statusClass) && defined($statusClass . '::STATUS_ERROR')) {
                    $span->setStatus(constant($statusClass . '::STATUS_ERROR'));
                }
            }
        } finally {
            if ($span !== null && method_exists($span, 'end')) {
                try {
                    $span->end();
                } catch (\Throwable $e) {
                    // Abaikan.
                }
            }
        }
    }

    /**
     * Daftar event yang dikenali (mirror SecurePayload::EVENT_*).
     *
     * @return list<string>
     */
    public static function knownEvents(): array
    {
        return [
            SecurePayload::EVENT_TIMESTAMP_INVALID,
            SecurePayload::EVENT_REPLAY_DETECTED,
            SecurePayload::EVENT_DECRYPT_FAILED,
            SecurePayload::EVENT_SIGNATURE_INVALID,
            SecurePayload::EVENT_KEY_NOT_FOUND,
            SecurePayload::EVENT_NONCE_MISMATCH,
        ];
    }
}
