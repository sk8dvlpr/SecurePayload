<?php
declare(strict_types=1);

namespace SecurePayload\Exceptions;

use RuntimeException;
use Throwable;

final class SecurePayloadException extends RuntimeException
{
    public const BAD_REQUEST = 400;
    public const UNAUTHORIZED = 401;
    public const UNPROCESSABLE = 422;
    public const SERVER_ERROR = 500;

    private array $context = [];

    /**
     * @param string           $message  Pesan error bahasa Indonesia.
     * @param int              $code     Kode error (salah satu konstanta class ini).
     * @param array<string,mixed> $context Konteks tambahan non-secret.
     * @param Throwable|null   $previous  Exception penyebab (chain tetap terjaga).
     */
    public function __construct(string $message, int $code = self::BAD_REQUEST, array $context = [], ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->context = $context;
    }

    public function getContext(): array
    {
        return $this->context;
    }
}
