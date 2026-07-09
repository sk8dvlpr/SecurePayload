<?php

declare(strict_types=1);

namespace SecurePayload\Protocol;

use SecurePayload\Exceptions\SecurePayloadException;

/**
 * Derivasi kunci HKDF-SHA256 untuk pemisahan domain subkey.
 */
final class Hkdf
{
    /**
     * Turunkan subkey 32-byte dari sebuah master key memakai HKDF-SHA256.
     *
     * Pemisahan domain berbasis parameter `info` (purpose): kunci untuk fungsi
     * berbeda (mis. enkripsi vs signing) tidak akan sama walau master-nya sama,
     * sehingga kebocoran satu subkey tidak otomatis membahayakan fungsi lain.
     *
     * @param string $master  Master key (≥1 byte; HMAC secret raw atau AEAD key raw).
     * @param string $purpose Label fungsi unik (lihat konstanta KDF_PURPOSE_*).
     * @param int    $len     Panjang subkey dalam byte (default 32).
     *
     * @return string Subkey biner sepanjang $len byte.
     * @throws SecurePayloadException Jika master kosong atau derivasi gagal.
     */
    public static function deriveKey(string $master, string $purpose, int $len = 32): string
    {
        if ($master === '') {
            throw new SecurePayloadException('Master key kosong untuk derivasi HKDF', SecurePayloadException::SERVER_ERROR);
        }
        // hash_hkdf melempar ValueError untuk algoritma/panjang tidak valid;
        // dengan sha256 + $len wajar, hasilnya selalu string biner sepanjang $len.
        return hash_hkdf('sha256', $master, $len, $purpose);
    }
}
