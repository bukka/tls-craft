<?php

declare(strict_types=1);

namespace Php\TlsCraft\Protocol;

/**
 * TLS Alert Levels
 */
enum AlertLevel: int
{
    case WARNING = 1;
    case FATAL = 2;

    public function toByte(): string
    {
        return chr($this->value);
    }

    public static function fromByte(string $byte): self
    {
        return self::from(ord($byte));
    }
}
