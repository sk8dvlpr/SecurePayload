<?php
declare(strict_types=1);

namespace SecurePayload\Observability;

use SecurePayload\SecurePayload;

/**
 * Exporter metrik Prometheus untuk event keamanan SecurePayload (Phase 15).
 *
 * Pasang callback dari {@see onSecurityEvent()} ke instance SecurePayload untuk
 * menghitung counter kegagalan verifikasi tanpa mengekspos secret/plaintext.
 *
 * Secara default hanya label `event` (cardinality rendah). Aktifkan
 * `includeClientId` / `includeKeyId` hanya bila Anda sadar risiko cardinality tinggi.
 */
final class PrometheusSecurityExporter
{
    private string $namespace;
    private bool $includeClientId;
    private bool $includeKeyId;

    /** @var array<string,int> key = serialized label set */
    private array $counters = [];

    /**
     * @param array<string,mixed> $opts
     *   - namespace: string (default 'securepayload')
     *   - includeClientId: bool (default false)
     *   - includeKeyId: bool (default false)
     */
    public function __construct(array $opts = [])
    {
        $this->namespace = is_string($opts['namespace'] ?? null) && $opts['namespace'] !== ''
            ? (string) $opts['namespace']
            : 'securepayload';
        $this->includeClientId = !empty($opts['includeClientId']);
        $this->includeKeyId = !empty($opts['includeKeyId']);
    }

    /**
     * Factory callback untuk opsi `onSecurityEvent` di SecurePayload.
     *
     * @return callable(string, array<string,mixed>): void
     */
    public function onSecurityEvent(): callable
    {
        return function (string $event, array $context): void {
            $this->record($event, $context);
        };
    }

    /**
     * Catat satu event keamanan (aman dipanggil langsung untuk testing).
     *
     * @param array<string,mixed> $context
     */
    public function record(string $event, array $context): void
    {
        $labels = ['event' => $event];
        if ($this->includeClientId && isset($context['clientId'])) {
            $labels['client_id'] = (string) $context['clientId'];
        }
        if ($this->includeKeyId && isset($context['keyId'])) {
            $labels['key_id'] = (string) $context['keyId'];
        }
        $key = $this->labelKey($labels);
        $this->counters[$key] = ($this->counters[$key] ?? 0) + 1;
    }

    /**
     * Render metrik dalam format Prometheus text 0.0.4.
     */
    public function render(): string
    {
        $metric = $this->namespace . '_security_events_total';
        $lines = [];
        $lines[] = '# HELP ' . $metric . ' Total event keamanan SecurePayload';
        $lines[] = '# TYPE ' . $metric . ' counter';

        if ($this->counters === []) {
            $lines[] = $metric . '{event=""} 0';
            return implode("\n", $lines) . "\n";
        }

        ksort($this->counters);
        foreach ($this->counters as $key => $value) {
            $labels = $this->labelKeyDecode($key);
            $parts = [];
            foreach ($labels as $k => $v) {
                $parts[] = $k . '="' . self::escapeLabel((string) $v) . '"';
            }
            $lines[] = $metric . '{' . implode(',', $parts) . '} ' . $value;
        }

        return implode("\n", $lines) . "\n";
    }

    /** Reset counter (hanya untuk testing). */
    public function reset(): void
    {
        $this->counters = [];
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

    /**
     * @param array<string,string> $labels
     */
    private function labelKey(array $labels): string
    {
        ksort($labels);
        return (string) json_encode($labels, JSON_UNESCAPED_SLASHES);
    }

    /**
     * @return array<string,string>
     */
    private function labelKeyDecode(string $key): array
    {
        $decoded = json_decode($key, true);
        return is_array($decoded) ? $decoded : [];
    }

    private static function escapeLabel(string $value): string
    {
        return str_replace(['\\', "\n", '"'], ['\\\\', '\\n', '\\"'], $value);
    }
}
