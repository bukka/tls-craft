<?php

namespace Php\TlsCraft\Crypto;

enum CipherSuite: int
{
    case TLS_AES_128_GCM_SHA256 = 0x1301;
    case TLS_AES_256_GCM_SHA384 = 0x1302;
    case TLS_CHACHA20_POLY1305_SHA256 = 0x1303;
    case TLS_AES_128_CCM_SHA256 = 0x1304;
    case TLS_AES_128_CCM_8_SHA256 = 0x1305;

    public function getHashAlgorithm(): string
    {
        return match ($this) {
            self::TLS_AES_128_GCM_SHA256,
            self::TLS_CHACHA20_POLY1305_SHA256,
            self::TLS_AES_128_CCM_SHA256,
            self::TLS_AES_128_CCM_8_SHA256 => 'sha256',
            self::TLS_AES_256_GCM_SHA384 => 'sha384',
        };
    }

    public function getKeyLength(): int
    {
        return match ($this) {
            self::TLS_AES_128_GCM_SHA256,
            self::TLS_AES_128_CCM_SHA256,
            self::TLS_AES_128_CCM_8_SHA256 => 16,
            self::TLS_AES_256_GCM_SHA384 => 32,
            self::TLS_CHACHA20_POLY1305_SHA256 => 32,
        };
    }

    public function getIVLength(): int
    {
        return match ($this) {
            self::TLS_AES_128_GCM_SHA256,
            self::TLS_AES_256_GCM_SHA384,
            self::TLS_AES_128_CCM_SHA256,
            self::TLS_AES_128_CCM_8_SHA256 => 12,
            self::TLS_CHACHA20_POLY1305_SHA256 => 12,
        };
    }

    public function getHashLength(): int
    {
        return match ($this) {
            self::TLS_AES_128_GCM_SHA256,
            self::TLS_CHACHA20_POLY1305_SHA256,
            self::TLS_AES_128_CCM_SHA256,
            self::TLS_AES_128_CCM_8_SHA256 => 32,
            self::TLS_AES_256_GCM_SHA384 => 48,
        };
    }

    public function getAEADAlgorithm(): string
    {
        return match ($this) {
            self::TLS_AES_128_GCM_SHA256 => 'aes-128-gcm',
            self::TLS_AES_256_GCM_SHA384 => 'aes-256-gcm',
            self::TLS_CHACHA20_POLY1305_SHA256 => 'chacha20-poly1305',
            self::TLS_AES_128_CCM_SHA256 => 'aes-128-ccm',
            self::TLS_AES_128_CCM_8_SHA256 => 'aes-128-ccm',
        };
    }
}
