<?php

declare(strict_types=1);

namespace SecurePayload\Crypto;

/**
 * Interface signer post-quantum (ML-DSA / Dilithium) untuk mode hybrid.
 *
 * Implementasi nyata (liboqs, etc.) di-inject via opsi konstruktor `pqSigner`.
 * Stub tes boleh dipakai hanya untuk uji format wire — bukan kriptografi nyata.
 */
interface PqSignerInterface
{
    /** Ukuran signature ML-DSA-44 dalam byte (standar FIPS 204). */
    public const MLDSA44_SIG_BYTES = 2420;

    /** Ukuran public key ML-DSA-44 dalam byte. */
    public const MLDSA44_PUBLIC_BYTES = 1312;

    /** Ukuran secret key ML-DSA-44 dalam byte. */
    public const MLDSA44_SECRET_BYTES = 2560;

    /**
     * Tanda tangani pesan; kembalikan signature mentah (panjang MLDSA44_SIG_BYTES untuk ML-DSA-44).
     */
    public function sign(string $msg): string;

    /**
     * Verifikasi signature terhadap public key mentah.
     */
    public function verify(string $msg, string $sig, string $publicKey): bool;
}
