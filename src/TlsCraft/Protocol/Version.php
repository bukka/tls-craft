<?php

declare(strict_types=1);

namespace Php\TlsCraft\Protocol;

use InvalidArgumentException;

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
        return $this === self::TLS_1_3;
    }

    public function getName(): string
    {
        return match($this) {
            self::TLS_1_0 => 'TLS 1.0',
            self::TLS_1_1 => 'TLS 1.1',
            self::TLS_1_2 => 'TLS 1.2',
            self::TLS_1_3 => 'TLS 1.3',
        };
    }

    public static function fromName(string $name): self
    {
        return match($name) {
            'TLS 1.0', 'tls_1_0', '1.0' => self::TLS_1_0,
            'TLS 1.1', 'tls_1_1', '1.1' => self::TLS_1_1,
            'TLS 1.2', 'tls_1_2', '1.2' => self::TLS_1_2,
            'TLS 1.3', 'tls_1_3', '1.3' => self::TLS_1_3,
            default => throw new InvalidArgumentException("Unknown TLS version: {$name}"),
        };
    }
}
