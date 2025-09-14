<?php

declare(strict_types=1);

namespace Php\TlsCraft\Protocol;

/**
 * TLS Protocol Version
 */
enum Version: int
{
    case TLS_1_0 = 0x0301;
    case TLS_1_1 = 0x0302;
    case TLS_1_2 = 0x0303;
    case TLS_1_3 = 0x0304;

    public function toBytes(): string
    {
        return pack('n', $this->value);
    }

    public static function fromBytes(string $bytes): self
    {
        $value = unpack('n', $bytes)[1];
        return self::from($value);
    }

    public function isSupported(): bool
    {
        return $this === self::TLS_1_3 || $this === self::TLS_1_2;
    }
}
