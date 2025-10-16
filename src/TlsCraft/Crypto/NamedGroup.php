<?php

namespace Php\TlsCraft\Crypto;

use InvalidArgumentException;

/**
 * Named Groups (Elliptic Curve Groups and Finite Field Groups)
 * RFC 8446 Section 4.2.7
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
            'P-256', 'secp256r1' => self::SECP256R1,
            'P-384', 'secp384r1' => self::SECP384R1,
            'P-521', 'secp521r1' => self::SECP521R1,
            'X25519', 'x25519' => self::X25519,
            'X448', 'x448' => self::X448,
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
        return in_array($this, [
            self::SECP256R1,
            self::SECP384R1,
            self::SECP521R1,
            self::X25519,
            self::X448
        ], true);
    }

    public function isFiniteField(): bool
    {
        return in_array($this, [
            self::FFDHE2048,
            self::FFDHE3072,
            self::FFDHE4096,
            self::FFDHE6144,
            self::FFDHE8192
        ], true);
    }

    /**
     * Get the size of the public key in bytes as transmitted in TLS
     * For ECDH curves, this is the uncompressed point format (0x04 + x + y)
     * For X25519/X448, this is the raw public key
     * For FFDHE groups, this is the size of the public value
     */
    public function getKeySize(): int
    {
        return match($this) {
            self::SECP256R1 => 65,   // 1 + 32 + 32 (uncompressed point)
            self::SECP384R1 => 97,   // 1 + 48 + 48 (uncompressed point)
            self::SECP521R1 => 133,  // 1 + 66 + 66 (uncompressed point)
            self::X25519 => 32,      // Raw 32-byte public key
            self::X448 => 56,        // Raw 56-byte public key
            self::FFDHE2048 => 256,  // 2048 bits / 8
            self::FFDHE3072 => 384,  // 3072 bits / 8
            self::FFDHE4096 => 512,  // 4096 bits / 8
            self::FFDHE6144 => 768,  // 6144 bits / 8
            self::FFDHE8192 => 1024, // 8192 bits / 8
            default => 0,
        };
    }

    /**
     * Get the coordinate size for elliptic curves (x or y coordinate length)
     * This is useful for parsing/constructing EC points
     */
    public function getCoordinateSize(): int
    {
        return match($this) {
            self::SECP256R1 => 32,
            self::SECP384R1 => 48,
            self::SECP521R1 => 66,
            default => 0,
        };
    }
}
