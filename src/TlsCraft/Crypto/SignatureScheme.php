<?php

namespace Php\TlsCraft\Crypto;

enum SignatureScheme: int
{
    case RSA_PKCS1_SHA256 = 0x0401;
    case RSA_PKCS1_SHA384 = 0x0501;
    case RSA_PKCS1_SHA512 = 0x0601;
    case ECDSA_SECP256R1_SHA256 = 0x0403;
    case ECDSA_SECP384R1_SHA384 = 0x0503;
    case ECDSA_SECP521R1_SHA512 = 0x0603;
    case RSA_PSS_RSAE_SHA256 = 0x0804;
    case RSA_PSS_RSAE_SHA384 = 0x0805;
    case RSA_PSS_RSAE_SHA512 = 0x0806;
    case ED25519 = 0x0807;
    case ED448 = 0x0808;
    case RSA_PSS_PSS_SHA256 = 0x0809;
    case RSA_PSS_PSS_SHA384 = 0x080a;
    case RSA_PSS_PSS_SHA512 = 0x080b;

    public function getHashAlgorithm(): string
    {
        return match ($this) {
            self::RSA_PKCS1_SHA256,
            self::ECDSA_SECP256R1_SHA256,
            self::RSA_PSS_RSAE_SHA256,
            self::RSA_PSS_PSS_SHA256 => 'sha256',
            self::RSA_PKCS1_SHA384,
            self::ECDSA_SECP384R1_SHA384,
            self::RSA_PSS_RSAE_SHA384,
            self::RSA_PSS_PSS_SHA384 => 'sha384',
            self::RSA_PKCS1_SHA512,
            self::ECDSA_SECP521R1_SHA512,
            self::RSA_PSS_RSAE_SHA512,
            self::RSA_PSS_PSS_SHA512 => 'sha512',
            self::ED25519,
            self::ED448 => '', // EdDSA doesn't use separate hash
        };
    }

    public function isECDSA(): bool
    {
        return match ($this) {
            self::ECDSA_SECP256R1_SHA256,
            self::ECDSA_SECP384R1_SHA384,
            self::ECDSA_SECP521R1_SHA512 => true,
            default => false
        };
    }

    public function isRSA(): bool
    {
        return match ($this) {
            self::RSA_PKCS1_SHA256,
            self::RSA_PKCS1_SHA384,
            self::RSA_PKCS1_SHA512,
            self::RSA_PSS_RSAE_SHA256,
            self::RSA_PSS_RSAE_SHA384,
            self::RSA_PSS_RSAE_SHA512,
            self::RSA_PSS_PSS_SHA256,
            self::RSA_PSS_PSS_SHA384,
            self::RSA_PSS_PSS_SHA512 => true,
            default => false
        };
    }

    public function isEdDSA(): bool
    {
        return match ($this) {
            self::ED25519, self::ED448 => true,
            default => false
        };
    }
}