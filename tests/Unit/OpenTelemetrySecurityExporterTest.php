<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\Observability\OpenTelemetrySecurityExporter;
use SecurePayload\SecurePayload;

final class OpenTelemetrySecurityExporterTest extends TestCase
{
    public function testNoOpWhenTracerMissing(): void
    {
        $exporter = new OpenTelemetrySecurityExporter();
        $cb = $exporter->onSecurityEvent();
        $cb(SecurePayload::EVENT_REPLAY_DETECTED, ['clientId' => 'c1']);
        $this->assertNull($exporter->startVerifySpan());
        $exporter->endVerifySpan(null, false);
        $this->assertTrue(true);
    }

    public function testRecordCreatesSpanWithAttributes(): void
    {
        $span = new class () {
            /** @var array<string,string> */
            public array $attrs = [];
            public bool $ended = false;
            public $status = null;

            public function setAttribute(string $key, $value): void
            {
                $this->attrs[$key] = (string) $value;
            }

            public function setStatus($status): void
            {
                $this->status = $status;
            }

            public function end(): void
            {
                $this->ended = true;
            }
        };

        $builder = new class ($span) {
            public function __construct(private object $span)
            {
            }

            public function startSpan(): object
            {
                return $this->span;
            }
        };

        $tracer = new class ($builder) {
            public function __construct(private object $builder)
            {
            }

            public function spanBuilder(string $name): object
            {
                return $this->builder;
            }
        };

        $exporter = new OpenTelemetrySecurityExporter([
            'tracer' => $tracer,
            'includeClientId' => true,
            'includeKeyId' => true,
        ]);

        $exporter->record(SecurePayload::EVENT_SIGNATURE_INVALID, [
            'clientId' => 'c1',
            'keyId' => 'k1',
            'alg' => 'hmac',
        ]);

        $this->assertTrue($span->ended);
        $this->assertSame('signature_invalid', $span->attrs['securepayload.event']);
        $this->assertSame('c1', $span->attrs['securepayload.client_id']);
        $this->assertSame('k1', $span->attrs['securepayload.key_id']);
    }

    public function testOnSecurityEventSwallowsTracerExceptions(): void
    {
        $tracer = new class () {
            public function spanBuilder(string $name): void
            {
                throw new \RuntimeException('otel down');
            }
        };

        $exporter = new OpenTelemetrySecurityExporter(['tracer' => $tracer]);
        $cb = $exporter->onSecurityEvent();
        $cb(SecurePayload::EVENT_DECRYPT_FAILED, []);
        $this->assertTrue(true);
    }

    public function testVerifySpanLifecycle(): void
    {
        $span = new class () {
            public bool $ended = false;
            public $status = null;

            public function setStatus($status): void
            {
                $this->status = $status;
            }

            public function end(): void
            {
                $this->ended = true;
            }
        };

        $tracer = new class ($span) {
            public function __construct(private object $span)
            {
            }

            public function spanBuilder(string $name): object
            {
                return new class ($this->span) {
                    public function __construct(private object $span)
                    {
                    }

                    public function startSpan(): object
                    {
                        return $this->span;
                    }
                };
            }
        };

        $exporter = new OpenTelemetrySecurityExporter(['tracer' => $tracer]);
        $handle = $exporter->startVerifySpan('securepayload.verify');
        $this->assertNotNull($handle);
        $exporter->endVerifySpan($handle, false);
        $this->assertTrue($span->ended);
    }

    public function testKnownEventsListMatchesSecurePayloadConstants(): void
    {
        $events = OpenTelemetrySecurityExporter::knownEvents();
        $this->assertContains(SecurePayload::EVENT_REPLAY_DETECTED, $events);
        $this->assertCount(6, $events);
    }
}
