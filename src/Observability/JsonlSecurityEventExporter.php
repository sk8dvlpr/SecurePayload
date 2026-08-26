<?php

declare(strict_types=1);

namespace SecurePayload\Observability;

/**
 * Exporter JSONL untuk event keamanan SecurePayload.
 *
 * Pasang callback dari {@see onSecurityEvent()} ke opsi `onSecurityEvent`
 * SecurePayload untuk menambahkan satu baris JSON per event ke file log
 * (append-only). Semantik mengikuti Internal\EventEmitter: kegagalan I/O
 * TIDAK pernah dilempar ke alur utama — diam-diam gagal dan pesannya
 * tersimpan, dapat dibaca via {@see getLastError()}.
 *
 * Format tiap baris (satu event = satu baris fisik, tanpa newline di
 * dalam nilai — newline diganti spasi):
 *
 *     {"ts":1770000000,"event":"signature_invalid","ctx":{"clientId":"c1"}}
 *
 * Kunci envelope hanya `ts`, `event`, `ctx` — exporter murni serialisasi
 * dan TIDAK pernah menambah field baru berisi secret. Konteks memang
 * non-secret by convention (lihat EventEmitter); nilai nested di-flatten
 * satu level agar baris tetap datar dan mudah diparse viewer.
 *
 * Rotasi by-size sederhana: saat ukuran file mencapai `maxSizeBytes`,
 * file digeser menjadi `<path>.1`, `<path>.2`, dst. hingga `maxFiles`
 * arsip (arsip tertua dihapus). Rotasi dinonaktifkan bila
 * `maxSizeBytes` = 0 (default).
 */
final class JsonlSecurityEventExporter
{
    private string $path;
    private int $maxSizeBytes;
    private int $maxFiles;

    /** @var callable Penghasil timestamp unix; default time() (injectable untuk test) */
    private $clock;

    /** @var string|null Pesan kegagalan operasi tulis terakhir; null saat sukses */
    private ?string $lastError = null;

    /**
     * Handle file persisten (lazy-open pada append pertama). Menahan handle
     * terbuka menghindari siklus open/close per event (terukur 5.5–11 ms →
     * ~23 µs/event). WAJIB ditutup sebelum rotasi — tanpa itu rename gagal
     * di Windows (handle mengunci file) dan di Linux event menyusul menulis
     * ke file yang sudah di-rename. Kunci flock tetap dipasang per tulis
     * agar aman lintas proses.
     *
     * @var resource|null
     */
    private $fh = null;

    /**
     * @param string $path Path file log JSONL (wajib, tidak boleh kosong).
     *                     Direktori induk harus sudah ada — exporter tidak
     *                     membuat direktori.
     * @param array<string,mixed> $opts
     *   - maxSizeBytes: int batas ukuran sebelum rotasi (default 0 = off)
     *   - maxFiles: int jumlah arsip `<path>.N` yang disimpan (default 3, min 1)
     *   - clock: callable tanpa argumen yang mengembalikan int unix timestamp
     *
     * @throws \InvalidArgumentException Bila path kosong.
     */
    public function __construct(string $path, array $opts = [])
    {
        if ($path === '') {
            throw new \InvalidArgumentException('Path file log JSONL wajib diisi.');
        }
        $this->path = $path;
        $this->maxSizeBytes = max(0, (int) ($opts['maxSizeBytes'] ?? 0));
        $this->maxFiles = max(1, (int) ($opts['maxFiles'] ?? 3));
        $clock = $opts['clock'] ?? null;
        $this->clock = is_callable($clock) ? $clock : static fn (): int => time();
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
     * Append satu event sebagai JSON-line. Tidak pernah melempar exception:
     * kegagalan apa pun (buka/kunci/tulis/rotasi/encode) ditelan dan dicatat
     * di {@see getLastError()} — observability tidak boleh mengganggu alur
     * utama. Sukses mengosongkan lastError.
     *
     * @param array<string,mixed> $context WAJIB non-secret
     */
    public function record(string $event, array $context): void
    {
        try {
            $this->rotateIfNeeded();
            $this->append($this->buildLine($event, $context));
            $this->lastError = null;
        } catch (\Throwable $e) {
            // Sengaja ditelan: semantik EventEmitter — observability tidak
            // boleh mengubah hasil/keamanan alur utama.
            $this->lastError = get_class($e) . ': ' . $e->getMessage();
        }
    }

    /**
     * Tutup handle file log secara eksplisit (untuk long-running worker
     * sebelum idle panjang, atau saat pemanggil ingin melepas FD). Aman
     * dipanggil berkali-kali; otomatis juga dipanggil via __destruct.
     */
    public function close(): void
    {
        if (is_resource($this->fh)) {
            @fclose($this->fh);
        }
        $this->fh = null;
    }

    public function __destruct()
    {
        $this->close();
    }

    /**
     * Pesan kegagalan operasi tulis terakhir, atau null bila operasi
     * terakhir sukses / belum pernah menulis.
     */
    public function getLastError(): ?string
    {
        return $this->lastError;
    }

    /**
     * Path file log yang dipakai exporter (untuk debugging/pemasangan).
     */
    public function getPath(): string
    {
        return $this->path;
    }

    /**
     * Susun satu baris JSON dari event + context (sudah disanitasi).
     */
    private function buildLine(string $event, array $context): string
    {
        $line = json_encode(
            [
                'ts' => (int) ($this->clock)(),
                'event' => self::cleanText($event),
                'ctx' => self::flattenContext($context),
            ],
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
        );
        if ($line === false) {
            throw new \RuntimeException('json_encode gagal: ' . json_last_error_msg());
        }
        return $line;
    }

    /**
     * Append atomik dengan handle persisten: lazy-open 'ab' sekali, lalu
     * flock LOCK_EX + satu fwrite per event (handle tetap terbuka).
     * Semua fungsi I/O dipanggil dengan error suppression karena kegagalan
     * dikomunikasikan lewat exception yang ditelan {@see record()}.
     */
    private function append(string $line): void
    {
        if (!is_resource($this->fh)) {
            $fh = @fopen($this->path, 'ab');
            if ($fh === false) {
                throw new \RuntimeException('Gagal membuka file log: ' . $this->path);
            }
            $this->fh = $fh;
        }
        @flock($this->fh, LOCK_EX);
        $written = @fwrite($this->fh, $line . "\n");
        @flock($this->fh, LOCK_UN);
        if ($written === false) {
            // Handle bisa jadi tidak valid lagi (file dihapus/disk penuh):
            // buang agar append berikutnya lazy-open ulang dari nol.
            $this->close();
            throw new \RuntimeException('Gagal menulis ke file log: ' . $this->path);
        }
    }

    /**
     * Rotasi by-size sederhana: geser `<path>.{n-1}` → `<path>.{n}`
     * (hapus tertua), lalu `<path>` → `<path>.1`. Gagal rotasi = event
     * tersebut tidak ditulis (mencegah pertumbuhan tanpa batas); pesan
     * tersimpan di lastError.
     */
    private function rotateIfNeeded(): void
    {
        if ($this->maxSizeBytes <= 0 || !is_file($this->path)) {
            return;
        }
        clearstatcache(true, $this->path);
        $size = @filesize($this->path);
        if ($size === false || $size < $this->maxSizeBytes) {
            return;
        }
        // Tutup handle SEBELUM rename: dengan handle terbuka, rename gagal
        // di Windows (file terkunci) dan di Linux tulisan berikutnya masuk
        // ke file lama yang sudah di-rename. Handle di-reset; append
        // berikutnya lazy-open file baru.
        $this->close();
        $oldest = $this->path . '.' . $this->maxFiles;
        if (is_file($oldest)) {
            @unlink($oldest);
        }
        for ($i = $this->maxFiles - 1; $i >= 1; $i--) {
            $from = $this->path . '.' . $i;
            if (is_file($from)) {
                @rename($from, $this->path . '.' . ($i + 1));
            }
        }
        if (!@rename($this->path, $this->path . '.1')) {
            throw new \RuntimeException('Rotasi log gagal: ' . $this->path);
        }
    }

    /**
     * Sanitasi teks: buang CR/LF (diganti spasi) agar baris tetap satu
     * baris fisik walau nilai berisi input tak tepercaya.
     */
    private static function cleanText(string $value): string
    {
        return str_replace(["\r\n", "\r", "\n"], ' ', $value);
    }

    /**
     * Stringify nilai aman untuk log: string/int/float/bool/null langsung,
     * struktur lain di-encode JSON ringkas. Output dijamin bebas newline.
     *
     * @param mixed $value
     */
    private static function stringifyValue($value): string
    {
        if (is_string($value)) {
            return self::cleanText($value);
        }
        if (is_int($value)) {
            return (string) $value;
        }
        if (is_float($value)) {
            return (string) $value;
        }
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if ($value === null) {
            return '';
        }
        $encoded = json_encode(
            $value,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
        );
        return $encoded === false ? get_debug_type($value) : self::cleanText($encoded);
    }

    /**
     * Flatten context satu level: nilai array dirender ulang sebagai daftar
     * `key=value` (assoc) atau nilai polos (list), elemen nested lebih
     * dalam di-encode JSON ringkas. Kunci context dipertahankan seperti
     * adanya — exporter tidak menambah/mengubah field.
     *
     * @param array<string,mixed> $context
     *
     * @return array<string,string>
     */
    private static function flattenContext(array $context): array
    {
        $out = [];
        foreach ($context as $key => $value) {
            $out[(string) $key] = is_array($value)
                ? implode(', ', self::flattenArrayLevel($value))
                : self::stringifyValue($value);
        }
        return $out;
    }

    /**
     * Render isi array satu level menjadi daftar string pendek.
     *
     * @param array<mixed> $items
     *
     * @return list<string>
     */
    private static function flattenArrayLevel(array $items): array
    {
        $out = [];
        foreach ($items as $key => $item) {
            $rendered = self::stringifyValue($item);
            $out[] = is_string($key) && $key !== ''
                ? self::cleanText($key) . '=' . $rendered
                : $rendered;
        }
        return $out;
    }
}
