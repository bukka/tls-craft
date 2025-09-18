<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CryptoException;

use const OPENSSL_ALGO_SHA256;
use const OPENSSL_ALGO_SHA384;
use const OPENSSL_ALGO_SHA512;

class CertificateUtils
{
    public static function parseCertificate(string $certData): array
    {
        $cert = openssl_x509_parse($certData);
        if ($cert === false) {
            throw new CryptoException('Failed to parse certificate');
        }

        return $cert;
    }

    public static function getPublicKey(string $certData)
    {
        $publicKey = openssl_pkey_get_public($certData);
        if ($publicKey === false) {
            throw new CryptoException('Failed to extract public key from certificate');
        }

        return $publicKey;
    }

    public static function verifySignature(
        string $data,
        string $signature,
        $publicKey,
        SignatureScheme $scheme,
    ): bool {
        if ($scheme->isRSA()) {
            $algorithm = match($scheme) {
                SignatureScheme::RSA_PKCS1_SHA256 => OPENSSL_ALGO_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384 => OPENSSL_ALGO_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512 => OPENSSL_ALGO_SHA512,
                default => throw new CryptoException('Unsupported RSA signature scheme'),
            };

            return openssl_verify($data, $signature, $publicKey, $algorithm) === 1;
        }

        if ($scheme->isECDSA()) {
            $algorithm = match($scheme) {
                SignatureScheme::ECDSA_SECP256R1_SHA256 => OPENSSL_ALGO_SHA256,
                SignatureScheme::ECDSA_SECP384R1_SHA384 => OPENSSL_ALGO_SHA384,
                SignatureScheme::ECDSA_SECP521R1_SHA512 => OPENSSL_ALGO_SHA512,
                default => throw new CryptoException('Unsupported ECDSA signature scheme'),
            };

            return openssl_verify($data, $signature, $publicKey, $algorithm) === 1;
        }

        throw new CryptoException("Unsupported signature scheme: {$scheme->name}");
    }

    public static function createSignature(
        string $data,
        $privateKey,
        SignatureScheme $scheme,
    ): string {
        $signature = '';

        if ($scheme->isRSA()) {
            $algorithm = match($scheme) {
                SignatureScheme::RSA_PKCS1_SHA256 => OPENSSL_ALGO_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384 => OPENSSL_ALGO_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512 => OPENSSL_ALGO_SHA512,
                default => throw new CryptoException('Unsupported RSA signature scheme'),
            };

            if (!openssl_sign($data, $signature, $privateKey, $algorithm)) {
                throw new CryptoException('Failed to create RSA signature');
            }
        } elseif ($scheme->isECDSA()) {
            $algorithm = match($scheme) {
                SignatureScheme::ECDSA_SECP256R1_SHA256 => OPENSSL_ALGO_SHA256,
                SignatureScheme::ECDSA_SECP384R1_SHA384 => OPENSSL_ALGO_SHA384,
                SignatureScheme::ECDSA_SECP521R1_SHA512 => OPENSSL_ALGO_SHA512,
                default => throw new CryptoException('Unsupported ECDSA signature scheme'),
            };

            if (!openssl_sign($data, $signature, $privateKey, $algorithm)) {
                throw new CryptoException('Failed to create ECDSA signature');
            }
        } else {
            throw new CryptoException("Unsupported signature scheme: {$scheme->name}");
        }

        return $signature;
    }
}
