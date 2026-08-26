<?php
declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SecurePayload\Internal\EventEmitter;

final class EventEmitterTest extends TestCase
{
    public function testNullHandlerIsNoop(): void
    {
        $emitter = new EventEmitter(null);
        // Tidak boleh melempar apa pun.
        $emitter->emit('file_stored', ['keyId' => 'k1']);
        $emitter->emit('file_deleted');
        $this->expectNotToPerformAssertions();
    }

    public function testHandlerReceivesEventNameAndContext(): void
    {
        $received = [];
        $emitter = new EventEmitter(function (string $event, array $context) use (&$received): void {
            $received[] = [$event, $context];
        });

        $emitter->emit('file_accessed', ['clientId' => 'c1', 'keyId' => 'k1']);
        $emitter->emit('payload_schema_invalid');

        $this->assertSame([
            ['file_accessed', ['clientId' => 'c1', 'keyId' => 'k1']],
            ['payload_schema_invalid', []],
        ], $received);
    }

    public function testThrowingHandlerDoesNotBreakCaller(): void
    {
        $emitter = new EventEmitter(function (string $event, array $context): void {
            if ($event === 'boom_exception') {
                throw new \RuntimeException('handler gagal');
            }
            throw new \Error('handler error');
        });

        $reachedAfterEmit = false;

        try {
            $emitter->emit('boom_exception', []);
            $emitter->emit('boom_error', []);
            $reachedAfterEmit = true;
        } finally {
            $this->assertTrue($reachedAfterEmit, 'emit() tidak boleh melempar Throwable dari handler');
        }
    }
}
