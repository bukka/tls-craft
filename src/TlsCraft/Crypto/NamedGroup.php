<?php

namespace Php\TlsCraft\Crypto;

use InvalidArgumentException;

/**
 * Named Groups (Elliptic Curve Groups and Finite Field Groups)
 * RFC 8446 Section 4.2.7
 */
enum NamedGroup: int implements \JsonSerializable
{
    // Elliptic Curve Groups (ECDH, deprecated - TLS 1.2 and earlier)
    case SECT163K1 = 1;
    case SECT163R1 = 2;
    case SECT163R2 = 3;
    case SECT193R1 = 4;
    case SECT193R2 = 5;
    case SECT233K1 = 6;
    case SECT233R1 = 7;
    case SECT239K1 = 8;
    case SECT283K1 = 9;
    case SECT283R1 = 10;
    case SECT409K1 = 11;
    case SECT409R1 = 12;
    case SECT571K1 = 13;
    case SECT571R1 = 14;
    case SECP160K1 = 15;
    case SECP160R1 = 16;
    case SECP160R2 = 17;
    case SECP192K1 = 18;
    case SECP192R1 = 19;
    case SECP224K1 = 20;
    case SECP224R1 = 21;
    case SECP256K1 = 22;

    // Elliptic Curve Groups (RFC 8446)
    case SECP256R1 = 23;        // P-256
    case SECP384R1 = 24;        // P-384
    case SECP521R1 = 25;        // P-521

    // Brainpool curves (RFC 7027)
    case BRAINPOOLP256R1 = 26;
    case BRAINPOOLP384R1 = 27;
    case BRAINPOOLP512R1 = 28;

    // Modern curves
    case X25519 = 29;           // X25519
    case X448 = 30;             // X448

    // Brainpool curves for TLS 1.3 (RFC 8734)
    case BRAINPOOLP256R1TLS13 = 31;
    case BRAINPOOLP384R1TLS13 = 32;
    case BRAINPOOLP512R1TLS13 = 33;

    // Finite Field Groups (RFC 7919)
    case FFDHE2048 = 256;
    case FFDHE3072 = 257;
    case FFDHE4096 = 258;
    case FFDHE6144 = 259;
    case FFDHE8192 = 260;

    // Post-Quantum Hybrid Groups (draft-ietf-tls-ecdhe-mlkem)
    case SECP256R1MLKEM768 = 4587;      // 0x11EB
    case X25519MLKEM768 = 4588;         // 0x11EC
    case SECP384R1MLKEM1024 = 4589;     // 0x11ED

    // Arbitrary explicit prime curves (deprecated)
    case ARBITRARY_EXPLICIT_PRIME_CURVES = 65281;
    case ARBITRARY_EXPLICIT_CHAR2_CURVES = 65282;

    // Reserved for Private Use
    case PRIVATE_USE_START = 65280;
    case PRIVATE_USE_END = 65535;

    public static function fromName(string $name): self
    {
        return match($name) {
            'sect163k1' => self::SECT163K1,
            'sect163r1' => self::SECT163R1,
            'sect163r2' => self::SECT163R2,
            'sect193r1' => self::SECT193R1,
            'sect193r2' => self::SECT193R2,
            'sect233k1' => self::SECT233K1,
            'sect233r1' => self::SECT233R1,
            'sect239k1' => self::SECT239K1,
            'sect283k1' => self::SECT283K1,
            'sect283r1' => self::SECT283R1,
            'sect409k1' => self::SECT409K1,
            'sect409r1' => self::SECT409R1,
            'sect571k1' => self::SECT571K1,
            'sect571r1' => self::SECT571R1,
            'secp160k1' => self::SECP160K1,
            'secp160r1' => self::SECP160R1,
            'secp160r2' => self::SECP160R2,
            'secp192k1' => self::SECP192K1,
            'secp192r1' => self::SECP192R1,
            'secp224k1' => self::SECP224K1,
            'secp224r1' => self::SECP224R1,
            'secp256k1' => self::SECP256K1,
            'P-256', 'secp256r1' => self::SECP256R1,
            'P-384', 'secp384r1' => self::SECP384R1,
            'P-521', 'secp521r1' => self::SECP521R1,
            'brainpoolP256r1' => self::BRAINPOOLP256R1,
            'brainpoolP384r1' => self::BRAINPOOLP384R1,
            'brainpoolP512r1' => self::BRAINPOOLP512R1,
            'X25519', 'x25519' => self::X25519,
            'X448', 'x448' => self::X448,
            'brainpoolP256r1tls13' => self::BRAINPOOLP256R1TLS13,
            'brainpoolP384r1tls13' => self::BRAINPOOLP384R1TLS13,
            'brainpoolP512r1tls13' => self::BRAINPOOLP512R1TLS13,
            'ffdhe2048' => self::FFDHE2048,
            'ffdhe3072' => self::FFDHE3072,
            'ffdhe4096' => self::FFDHE4096,
            'ffdhe6144' => self::FFDHE6144,
            'ffdhe8192' => self::FFDHE8192,
            'SecP256r1MLKEM768', 'secp256r1mlkem768' => self::SECP256R1MLKEM768,
            'X25519MLKEM768', 'x25519mlkem768' => self::X25519MLKEM768,
            'SecP384r1MLKEM1024', 'secp384r1mlkem1024' => self::SECP384R1MLKEM1024,
            default => throw new InvalidArgumentException("Unknown named group: {$name}"),
        };
    }

    public function getName(): string
    {
        return match($this) {
            self::SECT163K1 => 'sect163k1',
            self::SECT163R1 => 'sect163r1',
            self::SECT163R2 => 'sect163r2',
            self::SECT193R1 => 'sect193r1',
            self::SECT193R2 => 'sect193r2',
            self::SECT233K1 => 'sect233k1',
            self::SECT233R1 => 'sect233r1',
            self::SECT239K1 => 'sect239k1',
            self::SECT283K1 => 'sect283k1',
            self::SECT283R1 => 'sect283r1',
            self::SECT409K1 => 'sect409k1',
            self::SECT409R1 => 'sect409r1',
            self::SECT571K1 => 'sect571k1',
            self::SECT571R1 => 'sect571r1',
            self::SECP160K1 => 'secp160k1',
            self::SECP160R1 => 'secp160r1',
            self::SECP160R2 => 'secp160r2',
            self::SECP192K1 => 'secp192k1',
            self::SECP192R1 => 'secp192r1',
            self::SECP224K1 => 'secp224k1',
            self::SECP224R1 => 'secp224r1',
            self::SECP256K1 => 'secp256k1',
            self::SECP256R1 => 'P-256',
            self::SECP384R1 => 'P-384',
            self::SECP521R1 => 'P-521',
            self::BRAINPOOLP256R1 => 'brainpoolP256r1',
            self::BRAINPOOLP384R1 => 'brainpoolP384r1',
            self::BRAINPOOLP512R1 => 'brainpoolP512r1',
            self::X25519 => 'X25519',
            self::X448 => 'X448',
            self::BRAINPOOLP256R1TLS13 => 'brainpoolP256r1tls13',
            self::BRAINPOOLP384R1TLS13 => 'brainpoolP384r1tls13',
            self::BRAINPOOLP512R1TLS13 => 'brainpoolP512r1tls13',
            self::FFDHE2048 => 'ffdhe2048',
            self::FFDHE3072 => 'ffdhe3072',
            self::FFDHE4096 => 'ffdhe4096',
            self::FFDHE6144 => 'ffdhe6144',
            self::FFDHE8192 => 'ffdhe8192',
            self::SECP256R1MLKEM768 => 'SecP256r1MLKEM768',
            self::X25519MLKEM768 => 'X25519MLKEM768',
            self::SECP384R1MLKEM1024 => 'SecP384r1MLKEM1024',
            self::ARBITRARY_EXPLICIT_PRIME_CURVES => 'arbitrary_explicit_prime_curves',
            self::ARBITRARY_EXPLICIT_CHAR2_CURVES => 'arbitrary_explicit_char2_curves',
            default => 'unknown_'.$this->value,
        };
    }

    public function isEllipticCurve(): bool
    {
        return $this->value >= 1 && $this->value <= 33;
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

    public function isPostQuantum(): bool
    {
        return in_array($this, [
            self::SECP256R1MLKEM768,
            self::X25519MLKEM768,
            self::SECP384R1MLKEM1024,
        ], true);
    }

    public function isDeprecated(): bool
    {
        // Curves 1-22 are deprecated/legacy
        return $this->value >= 1 && $this->value <= 22;
    }

    public function isTls13Compatible(): bool
    {
        return match($this) {
            self::SECP256R1,
            self::SECP384R1,
            self::SECP521R1,
            self::X25519,
            self::X448,
            self::BRAINPOOLP256R1TLS13,
            self::BRAINPOOLP384R1TLS13,
            self::BRAINPOOLP512R1TLS13,
            self::FFDHE2048,
            self::FFDHE3072,
            self::FFDHE4096,
            self::FFDHE6144,
            self::FFDHE8192,
            self::SECP256R1MLKEM768,
            self::X25519MLKEM768,
            self::SECP384R1MLKEM1024 => true,
            default => false,
        };
    }

    /**
     * Get the size of the public key in bytes as transmitted in TLS
     * For ECDH curves, this is the uncompressed point format (0x04 + x + y)
     * For X25519/X448, this is the raw public key
     * For FFDHE groups, this is the size of the public value
     * For PQC hybrids, this is the concatenated size
     */
    public function getKeySize(): int
    {
        return match($this) {
            self::SECP160K1, self::SECP160R1, self::SECP160R2 => 41,   // 1 + 20 + 20
            self::SECP192K1, self::SECP192R1 => 49,                     // 1 + 24 + 24
            self::SECP224K1, self::SECP224R1 => 57,                     // 1 + 28 + 28
            self::SECP256K1, self::SECP256R1, self::BRAINPOOLP256R1,
            self::BRAINPOOLP256R1TLS13 => 65,                           // 1 + 32 + 32
            self::SECP384R1, self::BRAINPOOLP384R1,
            self::BRAINPOOLP384R1TLS13 => 97,                           // 1 + 48 + 48
            self::SECP521R1 => 133,                                     // 1 + 66 + 66
            self::BRAINPOOLP512R1, self::BRAINPOOLP512R1TLS13 => 129,  // 1 + 64 + 64
            self::X25519 => 32,                                         // Raw 32-byte public key
            self::X448 => 56,                                           // Raw 56-byte public key
            self::FFDHE2048 => 256,                                     // 2048 bits / 8
            self::FFDHE3072 => 384,                                     // 3072 bits / 8
            self::FFDHE4096 => 512,                                     // 4096 bits / 8
            self::FFDHE6144 => 768,                                     // 6144 bits / 8
            self::FFDHE8192 => 1024,                                    // 8192 bits / 8
            self::X25519MLKEM768 => 1216,                               // 1184 (MLKEM) + 32 (X25519)
            self::SECP256R1MLKEM768 => 1249,                            // 65 (P-256) + 1184 (MLKEM)
            self::SECP384R1MLKEM1024 => 1665,                           // 97 (P-384) + 1568 (MLKEM-1024)
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
            self::SECP160K1, self::SECP160R1, self::SECP160R2 => 20,
            self::SECP192K1, self::SECP192R1 => 24,
            self::SECP224K1, self::SECP224R1 => 28,
            self::SECP256K1, self::SECP256R1, self::BRAINPOOLP256R1,
            self::BRAINPOOLP256R1TLS13 => 32,
            self::SECP384R1, self::BRAINPOOLP384R1,
            self::BRAINPOOLP384R1TLS13 => 48,
            self::BRAINPOOLP512R1, self::BRAINPOOLP512R1TLS13 => 64,
            self::SECP521R1 => 66,
            default => 0,
        };
    }

    public function jsonSerialize(): mixed
    {
        return $this->getName();
    }
}
