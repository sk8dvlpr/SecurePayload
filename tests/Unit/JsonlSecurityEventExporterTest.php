<?php

declare(strict_types=1);

namespace SecurePayload\Tests\Unit;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use SecurePayload\Observability\JsonlSecurityEventExporter;
use SecurePayload\SecurePayload;

final class JsonlSecurityEventExporterTest extends TestCase
{
    private string $tmpDir;
    private string $logPath;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/sp-jsonl-test-' . uniqid('', true);
        $this->assertTrue(@mkdir($this->tmpDir), 'Gagal membuat direktori temp');
        $this->logPath = $this->tmpDir . '/events.jsonl';
    }

    protected function tearDown(): void
    {
        foreach (glob($this->tmpDir . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->tmpDir);
    }

    private function exporter(array $opts = []): JsonlSecurityEventExporter
    {
        return new JsonlSecurityEventExporter($this->logPath, ['clock' => static fn (): int => 1700000000] + $opts);
    }

    /**
     * @return list<array<string,mixed>>
     */
    private function readLines(string $path): array
    {
        $raw = (string) file_get_contents($path);
        $lines = array_values(array_filter(explode("\n", $raw), static fn (string $l): bool => trim($l) !== ''));
        return array_map(
            static fn (string $line): array => json_decode($line, true),
            $lines
        );
    }

    public function testAppendWritesValidJsonPerLine(): void
    {
        $exporter = $this->exporter();
        $cb = $exporter->onSecurityEvent();
        $cb(SecurePayload::EVENT_SIGNATURE_INVALID, ['clientId' => 'c1', 'keyId' => 'k1']);
        $cb(SecurePayload::EVENT_REPLAY_DETECTED, ['clientId' => 'c2']);

        $this->assertFileExists($this->logPath);
        $lines = $this->readLines($this->logPath);
        $this->assertCount(2, $lines);

        $this->assertSame(1700000000, $lines[0]['ts']);
        $this->assertSame('signature_invalid', $lines[0]['event']);
        $this->assertSame(['clientId' => 'c1', 'keyId' => 'k1'], $lines[0]['ctx']);

        $this->assertSame('replay_detected', $lines[1]['event']);
        $this->assertSame(['clientId' => 'c2'], $lines[1]['ctx']);
        $this->assertNull($exporter->getLastError());
    }

    public function testRotationBySizeKeepsMaxFilesArchives(): void
    {
        // Satu baris ± 80 byte → maxSizeBytes kecil memicu rotasi per event.
        $exporter = $this->exporter(['maxSizeBytes' => 50, 'maxFiles' => 3]);
        for ($i = 1; $i <= 5; $i++) {
            $exporter->record('evt_' . $i, ['n' => $i]);
        }
        $this->assertNull($exporter->getLastError());

        // File utama hanya berisi event terbaru; arsip bergeser .1..(.3).
        $main = $this->readLines($this->logPath);
        $this->assertCount(1, $main);
        $this->assertSame('evt_5', $main[0]['event']);

        $a1 = $this->readLines($this->logPath . '.1');
        $this->assertCount(1, $a1);
        $this->assertSame('evt_4', $a1[0]['event']);

        $a3 = $this->readLines($this->logPath . '.3');
        $this->assertCount(1, $a3);
        $this->assertSame('evt_2', $a3[0]['event']);

        // Arsip tertua (evt_1) sudah terhapus; tidak ada file melebihi maxFiles.
        $this->assertFileDoesNotExist($this->logPath . '.4');
    }

    public function testRotationDisabledByDefault(): void
    {
        $exporter = $this->exporter();
        for ($i = 1; $i <= 20; $i++) {
            $exporter->record('evt_' . $i, []);
        }
        $this->assertCount(20, $this->readLines($this->logPath));
        $this->assertFileDoesNotExist($this->logPath . '.1');
    }

    public function testNestedContextIsFlattenedOneLevel(): void
    {
        $exporter = $this->exporter();
        $exporter->record('nested_event', [
            'reason' => ['code' => 5, 'tags' => ['a', 'b'], 'deep' => ['x' => ['y' => 'z']]],
            'plain_list' => ['p1', 'p2'],
        ]);

        [$line] = $this->readLines($this->logPath);
        $this->assertSame('nested_event', $line['event']);
        // Level 2: kunci dipertahankan; level lebih dalam di-encode JSON ringkas.
        $this->assertSame('code=5, tags=["a","b"], deep={"x":{"y":"z"}}', $line['ctx']['reason']);
        $this->assertSame('p1, p2', $line['ctx']['plain_list']);
    }

    public function testNewlineInValuesIsStrippedSoLineStaysSingleLine(): void
    {
        $exporter = $this->exporter();
        $exporter->record("evil\r\nevent", [
            'clientId' => "c\n1",
            'detail' => "line1\nline2\rline3\r\nline4",
        ]);

        $raw = (string) file_get_contents($this->logPath);
        $physicalLines = explode("\n", $raw);
        // Satu record = satu baris fisik + newline penutup.
        $this->assertCount(2, $physicalLines);
        $this->assertSame('', $physicalLines[1]);

        [$line] = $this->readLines($this->logPath);
        $this->assertSame('evil event', $line['event']);
        $this->assertSame('c 1', $line['ctx']['clientId']);
        $this->assertSame('line1 line2 line3 line4', $line['ctx']['detail']);
    }

    public function testWriteFailureDoesNotThrowAndFillsLastError(): void
    {
        // Direktori induk sengaja tidak ada → fopen 'ab' gagal.
        $missing = new JsonlSecurityEventExporter($this->tmpDir . '/nope/sub/events.jsonl');

        $cb = $missing->onSecurityEvent();
        $cb(SecurePayload::EVENT_DECRYPT_FAILED, ['clientId' => 'cx']); // TIDAK throw — semantik EventEmitter.

        $this->assertNotNull($missing->getLastError());
        $this->assertStringContainsString('Gagal membuka file log', (string) $missing->getLastError());
    }

    public function testLastErrorClearedAfterSuccessfulWrite(): void
    {
        $badPath = new JsonlSecurityEventExporter($this->tmpDir . '/nope/sub/events.jsonl');
        $badPath->record('failing', []);
        $this->assertNotNull($badPath->getLastError());

        // Operasi berikutnya yang sukses mengosongkan lastError (per-instance).
        $good = new JsonlSecurityEventExporter($this->logPath, [
            'clock' => static fn (): int => 1700000000,
        ]);
        $good->record('ok_1', []);
        $good->record('ok_2', []);
        $this->assertNull($good->getLastError());
    }

    public function testInjectableClockDrivesTimestamp(): void
    {
        $exporter = new JsonlSecurityEventExporter($this->logPath, ['clock' => static fn (): int => 1234567890]);
        $exporter->record('timed', []);

        [$line] = $this->readLines($this->logPath);
        $this->assertSame(1234567890, $line['ts']);
    }

    public function testEmptyPathThrowsInvalidArgumentException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new JsonlSecurityEventExporter('');
    }

    public function testScalarTypesAreStringifiedSafely(): void
    {
        $exporter = $this->exporter();
        $exporter->record('scalars', [
            'i' => 42,
            'f' => 1.5,
            'b_true' => true,
            'b_false' => false,
            'n' => null,
        ]);

        [$line] = $this->readLines($this->logPath);
        $this->assertSame([
            'i' => '42',
            'f' => '1.5',
            'b_true' => 'true',
            'b_false' => 'false',
            'n' => '',
        ], $line['ctx']);
    }

    public function testRecordMatchesSecurePayloadKnownEvents(): void
    {
        $exporter = $this->exporter();
        foreach ([
            SecurePayload::EVENT_TIMESTAMP_INVALID,
            SecurePayload::EVENT_REPLAY_DETECTED,
            SecurePayload::EVENT_SIGNATURE_INVALID,
            SecurePayload::EVENT_FILE_ACCESS_DENIED,
        ] as $event) {
            $exporter->record($event, ['clientId' => 'audit', 'reason' => 'test']);
        }
        $lines = $this->readLines($this->logPath);
        $this->assertCount(4, $lines);
        $this->assertSame(SecurePayload::EVENT_REPLAY_DETECTED, $lines[1]['event']);
        $this->assertNull($exporter->getLastError());
    }
}
