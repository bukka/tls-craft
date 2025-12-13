<?php

namespace Php\TlsCraft\Crypto;

use InvalidArgumentException;
use JsonSerializable;
use ValueError;

enum SignatureScheme: int implements JsonSerializable
{
    // RSA PKCS1
    case RSA_PKCS1_SHA1 = 0x0201;
    case RSA_PKCS1_SHA224 = 0x0301;
    case RSA_PKCS1_SHA256 = 0x0401;
    case RSA_PKCS1_SHA384 = 0x0501;
    case RSA_PKCS1_SHA512 = 0x0601;

    // ECDSA
    case ECDSA_SECP256R1_SHA256 = 0x0403;
    case ECDSA_SECP384R1_SHA384 = 0x0503;
    case ECDSA_SECP521R1_SHA512 = 0x0603;

    // GOSTR (Russian GOST)
    case GOSTR34102012_256A = 0x0709;
    case GOSTR34102012_256B = 0x070A;
    case GOSTR34102012_256C = 0x070B;
    case GOSTR34102012_256D = 0x070C;
    case GOSTR34102012_512A = 0x070D;
    case GOSTR34102012_512B = 0x070E;
    case GOSTR34102012_512C = 0x070F;

    // SM2 (Chinese standard)
    case SM2SIG_SM3 = 0x0708;

    // RSA PSS RSAE
    case RSA_PSS_RSAE_SHA256 = 0x0804;
    case RSA_PSS_RSAE_SHA384 = 0x0805;
    case RSA_PSS_RSAE_SHA512 = 0x0806;

    // EdDSA
    case ED25519 = 0x0807;
    case ED448 = 0x0808;

    // RSA PSS PSS
    case RSA_PSS_PSS_SHA256 = 0x0809;
    case RSA_PSS_PSS_SHA384 = 0x080A;
    case RSA_PSS_PSS_SHA512 = 0x080B;

    // ECDSA with SHAKE (RFC 8692)
    case ECDSA_SHA3_224 = 0x0810;
    case ECDSA_SHA3_256 = 0x0811;
    case ECDSA_SHA3_384 = 0x0812;
    case ECDSA_SHA3_512 = 0x0813;

    // RSA PSS with SHAKE
    case RSA_PSS_RSAE_SHA3_256 = 0x0814;
    case RSA_PSS_RSAE_SHA3_384 = 0x0815;
    case RSA_PSS_RSAE_SHA3_512 = 0x0816;
    case RSA_PSS_PSS_SHA3_256 = 0x0817;
    case RSA_PSS_PSS_SHA3_384 = 0x0818;
    case RSA_PSS_PSS_SHA3_512 = 0x0819;

    // More ECDSA variants
    case ECDSA_BRAINPOOLP256R1_SHA256 = 0x081A;
    case ECDSA_BRAINPOOLP384R1_SHA384 = 0x081B;
    case ECDSA_BRAINPOOLP512R1_SHA512 = 0x081C;

    // ECCSI (RFC 6507)
    case ECCSI_SHA256 = 0x0904;

    // Brainpool curves (TLS 1.3)
    case ECDSA_BRAINPOOLP256R1TLS13_SHA256 = 0x0905;
    case ECDSA_BRAINPOOLP384R1TLS13_SHA384 = 0x0906;
    case ECDSA_BRAINPOOLP512R1TLS13_SHA512 = 0x0907;

    // Legacy (DSA - rarely used but may appear)
    case DSA_SHA1 = 0x0202;
    case DSA_SHA224 = 0x0302;
    case DSA_SHA256 = 0x0402;
    case DSA_SHA384 = 0x0502;
    case DSA_SHA512 = 0x0602;

    // ECDSA with SHA-1 (legacy)
    case ECDSA_SHA1 = 0x0203;

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
            self::GOSTR34102012_256A => 'gostr34102012_256a',
            self::GOSTR34102012_256B => 'gostr34102012_256b',
            self::GOSTR34102012_256C => 'gostr34102012_256c',
            self::GOSTR34102012_256D => 'gostr34102012_256d',
            self::GOSTR34102012_512A => 'gostr34102012_512a',
            self::GOSTR34102012_512B => 'gostr34102012_512b',
            self::GOSTR34102012_512C => 'gostr34102012_512c',
            self::SM2SIG_SM3 => 'sm2sig_sm3',
            self::RSA_PSS_RSAE_SHA256 => 'rsa_pss_rsae_sha256',
            self::RSA_PSS_RSAE_SHA384 => 'rsa_pss_rsae_sha384',
            self::RSA_PSS_RSAE_SHA512 => 'rsa_pss_rsae_sha512',
            self::ED25519 => 'ed25519',
            self::ED448 => 'ed448',
            self::RSA_PSS_PSS_SHA256 => 'rsa_pss_pss_sha256',
            self::RSA_PSS_PSS_SHA384 => 'rsa_pss_pss_sha384',
            self::RSA_PSS_PSS_SHA512 => 'rsa_pss_pss_sha512',
            self::ECDSA_SHA3_224 => 'ecdsa_sha3_224',
            self::ECDSA_SHA3_256 => 'ecdsa_sha3_256',
            self::ECDSA_SHA3_384 => 'ecdsa_sha3_384',
            self::ECDSA_SHA3_512 => 'ecdsa_sha3_512',
            self::RSA_PSS_RSAE_SHA3_256 => 'rsa_pss_rsae_sha3_256',
            self::RSA_PSS_RSAE_SHA3_384 => 'rsa_pss_rsae_sha3_384',
            self::RSA_PSS_RSAE_SHA3_512 => 'rsa_pss_rsae_sha3_512',
            self::RSA_PSS_PSS_SHA3_256 => 'rsa_pss_pss_sha3_256',
            self::RSA_PSS_PSS_SHA3_384 => 'rsa_pss_pss_sha3_384',
            self::RSA_PSS_PSS_SHA3_512 => 'rsa_pss_pss_sha3_512',
            self::ECDSA_BRAINPOOLP256R1_SHA256 => 'ecdsa_brainpoolP256r1_sha256',
            self::ECDSA_BRAINPOOLP384R1_SHA384 => 'ecdsa_brainpoolP384r1_sha384',
            self::ECDSA_BRAINPOOLP512R1_SHA512 => 'ecdsa_brainpoolP512r1_sha512',
            self::ECCSI_SHA256 => 'eccsi_sha256',
            self::ECDSA_BRAINPOOLP256R1TLS13_SHA256 => 'ecdsa_brainpoolP256r1tls13_sha256',
            self::ECDSA_BRAINPOOLP384R1TLS13_SHA384 => 'ecdsa_brainpoolP384r1tls13_sha384',
            self::ECDSA_BRAINPOOLP512R1TLS13_SHA512 => 'ecdsa_brainpoolP512r1tls13_sha512',
            self::DSA_SHA1 => 'dsa_sha1',
            self::DSA_SHA224 => 'dsa_sha224',
            self::DSA_SHA256 => 'dsa_sha256',
            self::DSA_SHA384 => 'dsa_sha384',
            self::DSA_SHA512 => 'dsa_sha512',
            self::ECDSA_SHA1 => 'ecdsa_sha1',
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
            'gostr34102012_256a' => self::GOSTR34102012_256A,
            'gostr34102012_256b' => self::GOSTR34102012_256B,
            'gostr34102012_256c' => self::GOSTR34102012_256C,
            'gostr34102012_256d' => self::GOSTR34102012_256D,
            'gostr34102012_512a' => self::GOSTR34102012_512A,
            'gostr34102012_512b' => self::GOSTR34102012_512B,
            'gostr34102012_512c' => self::GOSTR34102012_512C,
            'sm2sig_sm3' => self::SM2SIG_SM3,
            'rsa_pss_rsae_sha256' => self::RSA_PSS_RSAE_SHA256,
            'rsa_pss_rsae_sha384' => self::RSA_PSS_RSAE_SHA384,
            'rsa_pss_rsae_sha512' => self::RSA_PSS_RSAE_SHA512,
            'ed25519' => self::ED25519,
            'ed448' => self::ED448,
            'rsa_pss_pss_sha256' => self::RSA_PSS_PSS_SHA256,
            'rsa_pss_pss_sha384' => self::RSA_PSS_PSS_SHA384,
            'rsa_pss_pss_sha512' => self::RSA_PSS_PSS_SHA512,
            'ecdsa_sha3_224' => self::ECDSA_SHA3_224,
            'ecdsa_sha3_256' => self::ECDSA_SHA3_256,
            'ecdsa_sha3_384' => self::ECDSA_SHA3_384,
            'ecdsa_sha3_512' => self::ECDSA_SHA3_512,
            'rsa_pss_rsae_sha3_256' => self::RSA_PSS_RSAE_SHA3_256,
            'rsa_pss_rsae_sha3_384' => self::RSA_PSS_RSAE_SHA3_384,
            'rsa_pss_rsae_sha3_512' => self::RSA_PSS_RSAE_SHA3_512,
            'rsa_pss_pss_sha3_256' => self::RSA_PSS_PSS_SHA3_256,
            'rsa_pss_pss_sha3_384' => self::RSA_PSS_PSS_SHA3_384,
            'rsa_pss_pss_sha3_512' => self::RSA_PSS_PSS_SHA3_512,
            'ecdsa_brainpoolP256r1_sha256' => self::ECDSA_BRAINPOOLP256R1_SHA256,
            'ecdsa_brainpoolP384r1_sha384' => self::ECDSA_BRAINPOOLP384R1_SHA384,
            'ecdsa_brainpoolP512r1_sha512' => self::ECDSA_BRAINPOOLP512R1_SHA512,
            'eccsi_sha256' => self::ECCSI_SHA256,
            'ecdsa_brainpoolP256r1tls13_sha256' => self::ECDSA_BRAINPOOLP256R1TLS13_SHA256,
            'ecdsa_brainpoolP384r1tls13_sha384' => self::ECDSA_BRAINPOOLP384R1TLS13_SHA384,
            'ecdsa_brainpoolP512r1tls13_sha512' => self::ECDSA_BRAINPOOLP512R1TLS13_SHA512,
            'dsa_sha1' => self::DSA_SHA1,
            'dsa_sha224' => self::DSA_SHA224,
            'dsa_sha256' => self::DSA_SHA256,
            'dsa_sha384' => self::DSA_SHA384,
            'dsa_sha512' => self::DSA_SHA512,
            'ecdsa_sha1' => self::ECDSA_SHA1,
            default => throw new InvalidArgumentException("Unknown signature scheme: {$name}"),
        };
    }

    /**
     * Decode a signature scheme from its numeric value
     */
    public static function decode(int $value): self
    {
        try {
            return self::from($value);
        } catch (ValueError $e) {
            throw new InvalidArgumentException('Unknown signature scheme value: 0x'.dechex($value)." ({$value})");
        }
    }

    /**
     * Encode the signature scheme to its wire format (2 bytes)
     */
    public function encode(): string
    {
        return pack('n', $this->value);
    }

    public function getHashAlgorithm(): string
    {
        return match ($this) {
            self::RSA_PKCS1_SHA1,
            self::DSA_SHA1,
            self::ECDSA_SHA1 => 'sha1',
            self::RSA_PKCS1_SHA224,
            self::DSA_SHA224,
            self::ECDSA_SHA3_224 => 'sha224',
            self::RSA_PKCS1_SHA256,
            self::ECDSA_SECP256R1_SHA256,
            self::ECCSI_SHA256,
            self::ECDSA_BRAINPOOLP256R1_SHA256,
            self::ECDSA_BRAINPOOLP256R1TLS13_SHA256,
            self::RSA_PSS_RSAE_SHA256,
            self::RSA_PSS_PSS_SHA256,
            self::DSA_SHA256,
            self::ECDSA_SHA3_256,
            self::RSA_PSS_RSAE_SHA3_256,
            self::RSA_PSS_PSS_SHA3_256 => 'sha256',
            self::RSA_PKCS1_SHA384,
            self::ECDSA_SECP384R1_SHA384,
            self::ECDSA_BRAINPOOLP384R1_SHA384,
            self::ECDSA_BRAINPOOLP384R1TLS13_SHA384,
            self::RSA_PSS_RSAE_SHA384,
            self::RSA_PSS_PSS_SHA384,
            self::DSA_SHA384,
            self::ECDSA_SHA3_384,
            self::RSA_PSS_RSAE_SHA3_384,
            self::RSA_PSS_PSS_SHA3_384 => 'sha384',
            self::RSA_PKCS1_SHA512,
            self::ECDSA_SECP521R1_SHA512,
            self::ECDSA_BRAINPOOLP512R1_SHA512,
            self::ECDSA_BRAINPOOLP512R1TLS13_SHA512,
            self::RSA_PSS_RSAE_SHA512,
            self::RSA_PSS_PSS_SHA512,
            self::DSA_SHA512,
            self::ECDSA_SHA3_512,
            self::RSA_PSS_RSAE_SHA3_512,
            self::RSA_PSS_PSS_SHA3_512 => 'sha512',
            self::ED25519,
            self::ED448 => '', // EdDSA doesn't use separate hash
            self::SM2SIG_SM3 => 'sm3',
            self::GOSTR34102012_256A,
            self::GOSTR34102012_256B,
            self::GOSTR34102012_256C,
            self::GOSTR34102012_256D => 'streebog256',
            self::GOSTR34102012_512A,
            self::GOSTR34102012_512B,
            self::GOSTR34102012_512C => 'streebog512',
        };
    }

    public function isECDSA(): bool
    {
        return match ($this) {
            self::ECDSA_SECP256R1_SHA256,
            self::ECDSA_SECP384R1_SHA384,
            self::ECDSA_SECP521R1_SHA512,
            self::ECCSI_SHA256,
            self::ECDSA_BRAINPOOLP256R1_SHA256,
            self::ECDSA_BRAINPOOLP384R1_SHA384,
            self::ECDSA_BRAINPOOLP512R1_SHA512,
            self::ECDSA_BRAINPOOLP256R1TLS13_SHA256,
            self::ECDSA_BRAINPOOLP384R1TLS13_SHA384,
            self::ECDSA_BRAINPOOLP512R1TLS13_SHA512,
            self::ECDSA_SHA3_224,
            self::ECDSA_SHA3_256,
            self::ECDSA_SHA3_384,
            self::ECDSA_SHA3_512,
            self::ECDSA_SHA1 => true,
            default => false,
        };
    }

    public function isRSAPKCS1(): bool
    {
        return in_array($this, [
            self::RSA_PKCS1_SHA256,
            self::RSA_PKCS1_SHA384,
            self::RSA_PKCS1_SHA512,
        ]);
    }

    public function isRSAPSS(): bool
    {
        return in_array($this, [
            self::RSA_PSS_RSAE_SHA256,
            self::RSA_PSS_RSAE_SHA384,
            self::RSA_PSS_RSAE_SHA512,
            self::RSA_PSS_PSS_SHA256,
            self::RSA_PSS_PSS_SHA384,
            self::RSA_PSS_PSS_SHA512,
        ]);
    }

    public function isRSA(): bool
    {
        return $this->isRSAPKCS1() || $this->isRSAPSS();
    }

    public function isEdDSA(): bool
    {
        return match ($this) {
            self::ED25519, self::ED448 => true,
            default => false,
        };
    }

    public function isDSA(): bool
    {
        return match ($this) {
            self::DSA_SHA1,
            self::DSA_SHA224,
            self::DSA_SHA256,
            self::DSA_SHA384,
            self::DSA_SHA512 => true,
            default => false,
        };
    }

    /**
     * Check if this signature scheme is compatible with TLS 1.3
     * TLS 1.3 doesn't support SHA-1 or SHA-224, and doesn't support DSA
     */
    public function isTls13Compatible(): bool
    {
        return match ($this) {
            self::RSA_PKCS1_SHA1,
            self::RSA_PKCS1_SHA224,
            self::DSA_SHA1,
            self::DSA_SHA224,
            self::DSA_SHA256,
            self::DSA_SHA384,
            self::DSA_SHA512,
            self::ECDSA_SHA1,
            self::ECDSA_SHA3_224 => false,
            default => true,
        };
    }

    public function jsonSerialize(): mixed
    {
        return $this->getName();
    }
}
