<?php

declare(strict_types=1);

namespace SecurePayload\File;

/**
 * Validasi keamanan file (dibagi antara payload base64 & streaming).
 */
final class FileValidation
{
    /**
     * Daftar ekstensi berbahaya bawaan (lowercase).
     *
     * @return list<string>
     */
    public static function dangerousExtList(): array
    {
        return ['php', 'php5', 'phtml', 'exe', 'dll', 'sh', 'bat', 'cmd', 'js', 'vbs', 'python', 'pl', 'cgi'];
    }

    /**
     * Map ekstensi → daftar MIME yang dianggap konsisten (anti-spoofing).
     *
     * @return array<string,list<string>>
     */
    public static function safeMimeMap(): array
    {
        return [
            'jpg' => ['image/jpeg', 'image/pjpeg'],
            'jpeg' => ['image/jpeg', 'image/pjpeg'],
            'png' => ['image/png'],
            'gif' => ['image/gif'],
            'webp' => ['image/webp'],
            'pdf' => ['application/pdf'],
            'txt' => ['text/plain'],
            'json' => ['application/json', 'text/plain'],
            'zip' => ['application/zip'],
            'doc' => ['application/msword'],
            'docx' => ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
            'xls' => ['application/vnd.ms-excel'],
            'xlsx' => ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
        ];
    }

    /**
     * MIME yang selalu diblokir apa pun ekstensinya (executable/script).
     *
     * @return list<string>
     */
    public static function dangerousMimeList(): array
    {
        return [
            'application/x-dosexec',
            'application/x-executable',
            'text/x-php',
            'application/x-php',
            'application/x-httpd-php',
            'text/x-shellscript',
        ];
    }

    /**
     * Validasi ekstensi terhadap allow-list & block-list (logika `block_dangerous`).
     *
     * @param array<string,mixed> $constraints
     * @return array{0:int,1:string}|null Tuple [status, pesan error] atau null bila lolos.
     */
    public static function fileExtensionError(string $ext, array $constraints): ?array
    {
        $blockVal = $constraints['block_dangerous'] ?? true;
        $dangerous = self::dangerousExtList();
        $shouldBlock = false;

        if (is_array($blockVal)) {
            // Blokir default + tambahan kustom.
            foreach ($blockVal as $b) {
                if (is_string($b)) {
                    $dangerous[] = $b;
                }
            }
            $shouldBlock = true;
        } elseif ($blockVal === true) {
            $shouldBlock = true;
        }

        $dangerous = array_map('strtolower', $dangerous);
        if ($shouldBlock && in_array($ext, $dangerous, true)) {
            return [422, "Ekstensi file berbahaya dideteksi (.$ext)"];
        }

        $allowedExts = $constraints['allowed_exts'] ?? [];
        if (is_array($allowedExts) && $allowedExts !== [] && !in_array($ext, array_map('strtolower', $allowedExts), true)) {
            return [422, "Ekstensi file tidak diizinkan (.$ext)"];
        }

        return null;
    }

    /**
     * Validasi MIME hasil sniffing (magic-byte) terhadap ekstensi + blokir MIME berbahaya.
     *
     * @param string $sniffBuffer Cukup beberapa byte awal file (header magic).
     * @return array{0:int,1:string}|null Tuple [status, pesan error] atau null bila lolos.
     */
    public static function fileMimeError(string $sniffBuffer, string $ext, bool $strict): ?array
    {
        if (!$strict) {
            return null;
        }
        $finfo = new \finfo(FILEINFO_MIME_TYPE);
        $realMime = $finfo->buffer($sniffBuffer) ?: 'application/octet-stream';

        $map = self::safeMimeMap();
        if (isset($map[$ext]) && !in_array($realMime, $map[$ext], true)) {
            return [422, "Security Alert: Isi file terdeteksi sebagai '$realMime' namun ekstensi adalah '.$ext'. (Spoofing Detected)"];
        }

        if (in_array($realMime, self::dangerousMimeList(), true)) {
            return [422, "Security Alert: Konten file terdeteksi berbahaya ($realMime)"];
        }

        return null;
    }

    /**
     * Sanitasi nama file untuk penyimpanan aman.
     * - basename (tolak path traversal)
     * - hapus NUL / kontrol char
     * - tolak nama reserved Windows (CON, PRN, AUX, NUL, COM1.., LPT1..)
     * - trim spasi/titik trailing (Windows)
     * - batasi panjang
     *
     * @return string Nama aman, atau 'unnamed' bila hasil kosong setelah sanitasi.
     */
    public static function sanitizeFileName(string $name): string
    {
        $name = str_replace("\0", "", $name);
        $name = str_replace(["\\", "/"], "/", $name);
        $name = basename($name);
        // Hapus karakter kontrol & RTL/bidi override.
        // NUL sudah dibuang di atas — jangan sertakan \x00 di pola (PHPStan: null byte in regex).
        $name = preg_replace('/[\x01-\x1F\x7F\x{202A}-\x{202E}\x{2066}-\x{2069}]/u', '', $name) ?? '';
        $name = trim($name, " \t.");
        if ($name === "" || $name === "." || $name === "..") {
            return "unnamed";
        }
        $stem = pathinfo($name, PATHINFO_FILENAME);
        $reserved = [
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ];
        if (in_array(strtoupper($stem), $reserved, true)) {
            $name = "_" . $name;
        }
        if (strlen($name) > 200) {
            $ext = pathinfo($name, PATHINFO_EXTENSION);
            $base = substr(pathinfo($name, PATHINFO_FILENAME), 0, 200 - ($ext !== "" ? strlen($ext) + 1 : 0));
            $name = $ext !== "" ? ($base . "." . $ext) : $base;
        }
        return $name !== "" ? $name : "unnamed";
    }

    /**
     * AAD konstan untuk secretstream, diikat ke versi protokol.
     */
    public static function streamAAD(string $version): string
    {
        return 'sp-stream-v' . $version;
    }

    /**
     * Baca tepat $len byte (loop sampai cukup atau EOF).
     *
     * @param resource $fh
     */
    public static function freadExact($fh, int $len): string
    {
        $buf = '';
        while (strlen($buf) < $len && !feof($fh)) {
            $r = fread($fh, $len - strlen($buf));
            if ($r === false || $r === '') {
                break;
            }
            $buf .= $r;
        }
        return $buf;
    }
}
