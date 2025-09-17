<?php

namespace Php\TlsCraft\Crypto;

enum SignatureScheme: int
{
    case RSA_PKCS1_SHA1 = 0x0201;
    case RSA_PKCS1_SHA224 = 0x0301;
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

    public function getName(): string
    {
        return match($this) {
            self::RSA_PKCS1_SHA1 => 'rsa_pkcs1_sha1',
            self::RSA_PKCS1_SHA224 => 'rsa_pkcs1_sha224',
            self::RSA_PKCS1_SHA256 => 'rsa_pkcs1_sha256',
            self::RSA_PKCS1_SHA384 => 'rsa_pkcs1_sha384',
            self::RSA_PKCS1_SHA512 => 'rsa_pkcs1_sha512',
            self::ECDSA_SECP256R1_SHA256 => 'ecdsa_secp256r1_sha256',
            self::ECDSA_SECP384R1_SHA384 => 'ecdsa_secp384r1_sha384',
            self::ECDSA_SECP521R1_SHA512 => 'ecdsa_secp521r1_sha512',
            self::RSA_PSS_RSAE_SHA256 => 'rsa_pss_rsae_sha256',
            self::RSA_PSS_RSAE_SHA384 => 'rsa_pss_rsae_sha384',
            self::RSA_PSS_RSAE_SHA512 => 'rsa_pss_rsae_sha512',
            self::RSA_PSS_PSS_SHA256 => 'rsa_pss_pss_sha256',
            self::RSA_PSS_PSS_SHA384 => 'rsa_pss_pss_sha384',
            self::RSA_PSS_PSS_SHA512 => 'rsa_pss_pss_sha512',
            default => 'unknown_' . $this->value
        };
    }

    public static function fromName(string $name): self
    {
        return match($name) {
            'rsa_pkcs1_sha1' => self::RSA_PKCS1_SHA1,
            'rsa_pkcs1_sha224' => self::RSA_PKCS1_SHA224,
            'rsa_pkcs1_sha256' => self::RSA_PKCS1_SHA256,
            'rsa_pkcs1_sha384' => self::RSA_PKCS1_SHA384,
            'rsa_pkcs1_sha512' => self::RSA_PKCS1_SHA512,
            'ecdsa_secp256r1_sha256' => self::ECDSA_SECP256R1_SHA256,
            'ecdsa_secp384r1_sha384' => self::ECDSA_SECP384R1_SHA384,
            'ecdsa_secp521r1_sha512' => self::ECDSA_SECP521R1_SHA512,
            'rsa_pss_rsae_sha256' => self::RSA_PSS_RSAE_SHA256,
            'rsa_pss_rsae_sha384' => self::RSA_PSS_RSAE_SHA384,
            'rsa_pss_rsae_sha512' => self::RSA_PSS_RSAE_SHA512,
            'rsa_pss_pss_sha256' => self::RSA_PSS_PSS_SHA256,
            'rsa_pss_pss_sha384' => self::RSA_PSS_PSS_SHA384,
            'rsa_pss_pss_sha512' => self::RSA_PSS_PSS_SHA512,
            default => throw new \InvalidArgumentException("Unknown signature scheme: {$name}")
        };
    }

    public function getHashAlgorithm(): string
    {
        return match ($this) {
            self::RSA_PKCS1_SHA1 => 'sha1',
            self::RSA_PKCS1_SHA224 => 'sha224',
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