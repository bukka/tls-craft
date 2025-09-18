<?php

namespace Php\TlsCraft\Crypto;

use InvalidArgumentException;

/**
 * Named Groups (Elliptic Curve Groups and Finite Field Groups)
 */
enum NamedGroup: int
{
    // Elliptic Curve Groups (RFC 8446)
    case SECP256R1 = 23;        // P-256
    case SECP384R1 = 24;        // P-384
    case SECP521R1 = 25;        // P-521
    case X25519 = 29;           // X25519
    case X448 = 30;             // X448

    // Finite Field Groups (RFC 7919)
    case FFDHE2048 = 256;
    case FFDHE3072 = 257;
    case FFDHE4096 = 258;
    case FFDHE6144 = 259;
    case FFDHE8192 = 260;

    // Reserved for Private Use
    case PRIVATE_USE_START = 65280;
    case PRIVATE_USE_END = 65535;

    public static function fromName(string $name): self
    {
        return match($name) {
            'P-256' => self::SECP256R1,
            'P-384' => self::SECP384R1,
            'P-521' => self::SECP521R1,
            'X25519' => self::X25519,
            'X448' => self::X448,
            'ffdhe2048' => self::FFDHE2048,
            'ffdhe3072' => self::FFDHE3072,
            'ffdhe4096' => self::FFDHE4096,
            'ffdhe6144' => self::FFDHE6144,
            'ffdhe8192' => self::FFDHE8192,
            default => throw new InvalidArgumentException("Unknown named group: {$name}"),
        };
    }

    public function getName(): string
    {
        return match($this) {
            self::SECP256R1 => 'P-256',
            self::SECP384R1 => 'P-384',
            self::SECP521R1 => 'P-521',
            self::X25519 => 'X25519',
            self::X448 => 'X448',
            self::FFDHE2048 => 'ffdhe2048',
            self::FFDHE3072 => 'ffdhe3072',
            self::FFDHE4096 => 'ffdhe4096',
            self::FFDHE6144 => 'ffdhe6144',
            self::FFDHE8192 => 'ffdhe8192',
            default => 'unknown_'.$this->value,
        };
    }

    public function isEllipticCurve(): bool
    {
        return $this->value < 256;
    }

    public function isFiniteField(): bool
    {
        return $this->value >= 256 && $this->value < 65280;
    }

    public function getKeySize(): int
    {
        return match($this) {
            self::SECP256R1, self::X25519 => 32,
            self::SECP384R1 => 48,
            self::SECP521R1 => 66,
            self::X448 => 56,
            self::FFDHE2048 => 256,
            self::FFDHE3072 => 384,
            self::FFDHE4096 => 512,
            self::FFDHE6144 => 768,
            self::FFDHE8192 => 1024,
            default => 0,
        };
    }
}
