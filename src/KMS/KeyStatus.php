<?php
declare(strict_types=1);

namespace SecurePayload\KMS;

/**
 * Konstanta status lifecycle kunci di database.
 */
final class KeyStatus
{
    public const ACTIVE = 'active';
    public const RETIRING = 'retiring';
    public const REVOKED = 'revoked';
    /** Kunci telah dihancurkan (destroy) — tidak dapat dipulihkan untuk dekripsi. */
    public const DESTROYED = 'destroyed';
}
