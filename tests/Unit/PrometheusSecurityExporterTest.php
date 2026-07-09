<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\Observability\PrometheusSecurityExporter;
use SecurePayload\SecurePayload;

final class PrometheusSecurityExporterTest extends TestCase
{
    public function testAllKnownEventsIncrementCounters(): void
    {
        $exporter = new PrometheusSecurityExporter();
        foreach (PrometheusSecurityExporter::knownEvents() as $event) {
            $exporter->record($event, ['clientId' => 'c1', 'keyId' => 'k1']);
        }
        $out = $exporter->render();
        foreach (PrometheusSecurityExporter::knownEvents() as $event) {
            $this->assertStringContainsString('event="' . $event . '"', $out);
        }
        $this->assertStringContainsString('# TYPE securepayload_security_events_total counter', $out);
    }

    public function testOptionalLabelsOnlyWhenEnabled(): void
    {
        $exporter = new PrometheusSecurityExporter();
        $exporter->record(SecurePayload::EVENT_REPLAY_DETECTED, ['clientId' => 'c1', 'keyId' => 'k1']);
        $out = $exporter->render();
        $this->assertStringNotContainsString('client_id=', $out);
        $this->assertStringNotContainsString('key_id=', $out);

        $withLabels = new PrometheusSecurityExporter(['includeClientId' => true, 'includeKeyId' => true]);
        $withLabels->record(SecurePayload::EVENT_REPLAY_DETECTED, ['clientId' => 'c1', 'keyId' => 'k1']);
        $labeled = $withLabels->render();
        $this->assertStringContainsString('client_id="c1"', $labeled);
        $this->assertStringContainsString('key_id="k1"', $labeled);
    }

    public function testOnSecurityEventCallbackDoesNotThrow(): void
    {
        $exporter = new PrometheusSecurityExporter();
        $cb = $exporter->onSecurityEvent();
        $cb(SecurePayload::EVENT_SIGNATURE_INVALID, ['clientId' => 'x', 'keyId' => 'y', 'alg' => 'hmac']);
        $this->assertStringContainsString('signature_invalid', $exporter->render());
    }

    public function testResetClearsCounters(): void
    {
        $exporter = new PrometheusSecurityExporter();
        $exporter->record(SecurePayload::EVENT_DECRYPT_FAILED, []);
        $exporter->reset();
        $out = $exporter->render();
        $this->assertStringContainsString('securepayload_security_events_total{event=""} 0', $out);
    }

    public function testCustomNamespace(): void
    {
        $exporter = new PrometheusSecurityExporter(['namespace' => 'myapp']);
        $exporter->record(SecurePayload::EVENT_KEY_NOT_FOUND, []);
        $this->assertStringContainsString('myapp_security_events_total', $exporter->render());
    }
}
