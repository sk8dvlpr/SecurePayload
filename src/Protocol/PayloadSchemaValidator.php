<?php

declare(strict_types=1);

namespace SecurePayload\Protocol;

/**
 * Validator subset JSON Schema untuk opsi server `payloadSchema` .
 *
 * Keyword yang didukung (tanpa dependency eksternal):
 *  - type            : string atau daftar tipe (object|array|string|number|integer|boolean|null)
 *  - properties      : skema per-field object
 *  - required        : daftar nama field wajib pada object
 *  - items           : skema untuk tiap elemen array
 *  - enum            : nilai harus salah satu dari daftar (pencocokan KETAT/strict —
 *                      1 ≠ "1" dan true ≠ 1, demi prediktabilitas & keamanan)
 *  - minimum/maximum : batas numerik
 *  - minLength/maxLength : batas panjang string
 *  - minItems/maxItems   : batas jumlah elemen array
 *  - pattern         : regex PCRE atas string (regex tidak valid = gagal fail-closed)
 *  - additionalProperties : false menolak field di luar `properties`
 *  - maxDepth        : guard kedalaman rekursi (default 16)
 *
 * Keyword lain di luar daftar diabaikan. Penerapan keyword mengikuti TIPE NILAI
 * aktual (bukan hanya deklarasi type), sesuai semantik JSON Schema.
 *
 * Konvensi return: null = valid; string = pesan error Indonesia siap dilaporkan.
 */
final class PayloadSchemaValidator
{
    /** Kedalaman rekursi default. */
    public const DEFAULT_MAX_DEPTH = 16;

    /** @var list<string> Tipe JSON Schema yang dikenali. */
    private const TIPE_DIKENALI = ['object', 'array', 'string', 'number', 'integer', 'boolean', 'null'];

    /**
     * Validasi nilai JSON terhadap skema.
     *
     * @param mixed $json Nilai hasil json_decode(body, true).
     * @param array<string,mixed> $schema Definisi skema (subset didukung).
     * @param int $maxDepth Batas kedalaman struktur bersarang.
     *
     * @return string|null null bila valid; pesan error Indonesia bila tidak.
     */
    public static function validate($json, array $schema, int $maxDepth = self::DEFAULT_MAX_DEPTH): ?string
    {
        return self::cek($json, $schema, '', 0, $maxDepth);
    }

    /**
     * Rekursi validasi satu level struktur.
     *
     * @param mixed $val Nilai yang divalidasi.
     * @param array<string,mixed> $sch Sub-skema berlaku untuk nilai ini.
     * @param string $path Jalur field untuk pesan error (mis. "items[2].nama").
     * @param int $depth Kedalaman rekursi saat ini (root = 0).
     * @param int $maxDepth Batas kedalaman maksimum.
     */
    private static function cek($val, array $sch, string $path, int $depth, int $maxDepth): ?string
    {
        if ($depth > $maxDepth) {
            return 'Kedalaman struktur melebihi batas ' . $maxDepth . ' level pada ' . self::lokasi($path);
        }

        // --- Keyword: type (string atau daftar tipe) ---
        if (array_key_exists('type', $sch)) {
            $tipeReq = $sch['type'];
            $daftarTipe = is_array($tipeReq) ? $tipeReq : [$tipeReq];
            // Tahap 1: validasi seluruh nama tipe lebih dahulu agar penolakan
            // konfigurasi salah tidak bergantung urutan (fail-closed deterministik).
            foreach ($daftarTipe as $t) {
                if (!is_string($t) || !in_array($t, self::TIPE_DIKENALI, true)) {
                    return 'Tipe "' . self::ringkas($t) . '" tidak dikenali pada skema ' . self::lokasi($path);
                }
            }
            // Tahap 2: semantik anyOf — cukup satu tipe yang cocok.
            $cocok = false;
            foreach ($daftarTipe as $t) {
                if (self::cocokTipe($val, (string) $t)) {
                    $cocok = true;
                    break;
                }
            }
            if (!$cocok) {
                return 'Tipe data ' . self::deskripsiTipe($val)
                    . ' tidak cocok dengan ekspektasi (' . implode('|', $daftarTipe)
                    . ') pada ' . self::lokasi($path);
            }
        }

        // --- Keyword: enum ---
        if (isset($sch['enum'])) {
            if (!is_array($sch['enum'])) {
                return 'Keyword enum harus berupa array pada skema ' . self::lokasi($path);
            }
            if (!in_array($val, $sch['enum'], true)) {
                return 'Nilai pada ' . self::lokasi($path) . ' tidak termasuk daftar enum yang diizinkan';
            }
        }

        // --- Keyword numerik: minimum / maximum ---
        if (is_int($val) || is_float($val)) {
            if (isset($sch['minimum']) && is_numeric($sch['minimum']) && $val < (float) $sch['minimum']) {
                return 'Nilai pada ' . self::lokasi($path) . ' harus >= ' . $sch['minimum'];
            }
            if (isset($sch['maximum']) && is_numeric($sch['maximum']) && $val > (float) $sch['maximum']) {
                return 'Nilai pada ' . self::lokasi($path) . ' harus <= ' . $sch['maximum'];
            }
        }

        // --- Keyword string: minLength / maxLength / pattern ---
        if (is_string($val)) {
            if (isset($sch['minLength']) && is_int($sch['minLength']) && strlen($val) < $sch['minLength']) {
                return 'Panjang string pada ' . self::lokasi($path) . ' harus >= ' . $sch['minLength'];
            }
            if (isset($sch['maxLength']) && is_int($sch['maxLength']) && strlen($val) > $sch['maxLength']) {
                return 'Panjang string pada ' . self::lokasi($path) . ' harus <= ' . $sch['maxLength'];
            }
            if (isset($sch['pattern'])) {
                if (!is_string($sch['pattern'])) {
                    return 'Keyword pattern harus string pada skema ' . self::lokasi($path);
                }
                $hasil = @preg_match($sch['pattern'], $val);
                if ($hasil === false) {
                    // Regex konfigurasi rusak → gagal tertutup, jangan diam-diam lolos.
                    return 'Pattern regex tidak valid pada skema ' . self::lokasi($path);
                }
                if ($hasil !== 1) {
                    return 'String pada ' . self::lokasi($path) . ' tidak cocok dengan pattern ' . $sch['pattern'];
                }
            }
        }

        // --- Keyword object: required / properties / additionalProperties ---
        if (is_array($val) && self::adalahObjek($val)) {
            if (isset($sch['required'])) {
                if (!is_array($sch['required'])) {
                    return 'Keyword required harus berupa array pada skema ' . self::lokasi($path);
                }
                foreach ($sch['required'] as $req) {
                    if (!is_string($req)) {
                        // Entry non-string = konfigurasi skema salah → ditolak fail-closed,
                        // konsisten dengan keyword lain (type/pattern/enum) — bukan diloloskan diam-diam.
                        return 'Keyword required harus berupa daftar nama field string pada skema ' . self::lokasi($path);
                    }
                    if (!array_key_exists($req, $val)) {
                        return "Field '{$req}' wajib ada pada " . self::lokasi($path);
                    }
                }
            }

            $props = isset($sch['properties']) && is_array($sch['properties']) ? $sch['properties'] : [];
            foreach ($val as $k => $child) {
                $cPath = $path === '' ? (string) $k : $path . '.' . $k;
                if (isset($props[$k]) && is_array($props[$k])) {
                    $err = self::cek($child, $props[$k], $cPath, $depth + 1, $maxDepth);
                    if ($err !== null) {
                        return $err;
                    }
                } elseif (($sch['additionalProperties'] ?? true) === false) {
                    return "Field '{$k}' tidak diizinkan (additionalProperties=false) pada " . self::lokasi($path);
                }
            }
        }

        // --- Keyword array: minItems / maxItems / items ---
        if (is_array($val) && self::adalahList($val)) {
            if (isset($sch['minItems']) && is_int($sch['minItems']) && count($val) < $sch['minItems']) {
                return 'Jumlah elemen array pada ' . self::lokasi($path) . ' harus >= ' . $sch['minItems'];
            }
            if (isset($sch['maxItems']) && is_int($sch['maxItems']) && count($val) > $sch['maxItems']) {
                return 'Jumlah elemen array pada ' . self::lokasi($path) . ' harus <= ' . $sch['maxItems'];
            }
            if (isset($sch['items']) && is_array($sch['items'])) {
                foreach ($val as $i => $child) {
                    $err = self::cek($child, $sch['items'], $path . '[' . $i . ']', $depth + 1, $maxDepth);
                    if ($err !== null) {
                        return $err;
                    }
                }
            }
        }

        return null;
    }

    /**
     * Apakah array berperilaku sebagai LIST JSON (indeks 0..n-1 berurutan).
     * Array kosong diperlakukan list DAN object sekaligus (ambiguitas bawaan
     * json_decode assoc untuk {} vs []).
     */
    private static function adalahList(array $a): bool
    {
        return $a === [] || array_values($a) === $a;
    }

    /**
     * Apakah array berperilaku sebagai OBJECT JSON (map string=>nilai).
     */
    private static function adalahObjek(array $a): bool
    {
        return $a === [] || !self::adalahList($a);
    }

    /** Cek kesesuaian nilai terhadap satu nama tipe. */
    private static function cocokTipe($val, string $tipe): bool
    {
        switch ($tipe) {
            case 'object':
                return is_array($val) && self::adalahObjek($val);
            case 'array':
                return is_array($val) && self::adalahList($val);
            case 'string':
                return is_string($val);
            case 'integer':
                return is_int($val);
            case 'number':
                return is_int($val) || is_float($val);
            case 'boolean':
                return is_bool($val);
            case 'null':
                return $val === null;
        }
        return false;
    }

    /** Label lokasi untuk pesan error. */
    private static function lokasi(string $path): string
    {
        return $path === '' ? '(root)' : "'" . $path . "'";
    }

    /** Deskripsi tipe nilai aktual untuk pesan error. */
    private static function deskripsiTipe($val): string
    {
        if (is_array($val)) {
            return self::adalahList($val) ? 'array' : 'object';
        }
        if (is_object($val)) {
            return 'non-skalar';
        }
        return gettype($val);
    }

    /** Ringkas nilai arbitrer untuk dimasukkan ke pesan error secara aman. */
    private static function ringkas($v): string
    {
        return is_scalar($v) ? (string) $v : gettype($v);
    }
}
