<?php
declare(strict_types=1);

namespace SecurePayload\Exceptions;

use RuntimeException;

final class SecurePayloadException extends RuntimeException
{
    public const BAD_REQUEST = 400;
    public const UNAUTHORIZED = 401;
    public const UNPROCESSABLE = 422;
    public const SERVER_ERROR = 500;

    private array $context = [];

    public function __construct(string $message, int $code = self::BAD_REQUEST, array $context = [])
    {
        parent::__construct($message, $code);
        $this->context = $context;
    }

    public function getContext(): array
    {
        return $this->context;
    }
}
