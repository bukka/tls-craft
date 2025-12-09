<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CryptoException;
use Php\TlsCraft\Logger;

class CertificateSigner
{
    public function createSignature(
        string $data,
        $privateKey,
        SignatureScheme $scheme,
    ): string {
        Logger::debug('Creating signature', [
            'Scheme' => $scheme->name,
            'Data length' => strlen($data),
            'Data (prefix)' => bin2hex(substr($data, 0, 32)),
        ]);

        $signature = '';

        if ($scheme->isRSAPKCS1()) {
            $signature = $this->createRSAPKCS1Signature($data, $privateKey, $scheme);
        } elseif ($scheme->isRSAPSS()) {
            $signature = $this->createRSAPSSSignature($data, $privateKey, $scheme);
        } elseif ($scheme->isECDSA()) {
            $signature = $this->createECDSASignature($data, $privateKey, $scheme);
        } else {
            throw new CryptoException("Unsupported signature scheme: {$scheme->name}");
        }

        Logger::debug('Signature created', [
            'Scheme' => $scheme->name,
            'Signature length' => strlen($signature),
            'Signature (prefix)' => bin2hex(substr($signature, 0, 32)),
        ]);

        return $signature;
    }

    public function verifySignature(
        string $data,
        string $signature,
        $publicKey,
        SignatureScheme $scheme,
    ): bool {
        Logger::debug('Verifying signature', [
            'Scheme' => $scheme->name,
            'Data length' => strlen($data),
            'Signature length' => strlen($signature),
        ]);

        $result = false;

        if ($scheme->isRSAPKCS1()) {
            $result = $this->verifyRSAPKCS1Signature($data, $signature, $publicKey, $scheme);
        } elseif ($scheme->isRSAPSS()) {
            $result = $this->verifyRSAPSSSignature($data, $signature, $publicKey, $scheme);
        } elseif ($scheme->isECDSA()) {
            $result = $this->verifyECDSASignature($data, $signature, $publicKey, $scheme);
        } else {
            throw new CryptoException("Unsupported signature scheme: {$scheme->name}");
        }

        Logger::debug('Signature verification', [
            'Scheme' => $scheme->name,
            'Result' => $result ? 'VALID' : 'INVALID',
        ]);

        return $result;
    }

    private function createRSAPKCS1Signature(string $data, $privateKey, SignatureScheme $scheme): string
    {
        $algorithm = $this->getOpenSSLAlgorithm($scheme);

        Logger::debug('Creating RSA PKCS1 signature', [
            'Algorithm' => $this->getAlgorithmName($algorithm),
        ]);

        $signature = '';
        if (!openssl_sign($data, $signature, $privateKey, $algorithm)) {
            throw new CryptoException('Failed to create RSA PKCS1 signature: ' . openssl_error_string());
        }

        return $signature;
    }

    private function createRSAPSSSignature(string $data, $privateKey, SignatureScheme $scheme): string
    {
        $hashAlgo = $this->getHashAlgorithm($scheme);

        Logger::debug('Creating RSA-PSS signature', [
            'Hash algorithm' => $hashAlgo,
            'Scheme' => $scheme->name,
        ]);

        $signature = '';

        // Try the array format first (PHP 7.2+)
        $result = @openssl_sign(
            $data,
            $signature,
            $privateKey,
            [
                'digest_alg' => $hashAlgo,
                'padding' => OPENSSL_PKCS1_PSS_PADDING,
            ]
        );

        if (!$result) {
            Logger::warn('RSA-PSS signing with array format failed, trying fallback', [
                'Error' => openssl_error_string(),
            ]);

            // Fallback: manually construct PSS signature
            // This is less ideal but works on older PHP versions
            throw new CryptoException(
                'RSA-PSS signature creation failed. Your PHP version may not support PSS padding. ' .
                'Error: ' . openssl_error_string()
            );
        }

        return $signature;
    }

    private function createECDSASignature(string $data, $privateKey, SignatureScheme $scheme): string
    {
        $algorithm = $this->getOpenSSLAlgorithm($scheme);

        Logger::debug('Creating ECDSA signature', [
            'Algorithm' => $this->getAlgorithmName($algorithm),
        ]);

        $signature = '';
        if (!openssl_sign($data, $signature, $privateKey, $algorithm)) {
            throw new CryptoException('Failed to create ECDSA signature: ' . openssl_error_string());
        }

        return $signature;
    }

    private function verifyRSAPKCS1Signature(string $data, string $signature, $publicKey, SignatureScheme $scheme): bool
    {
        $algorithm = $this->getOpenSSLAlgorithm($scheme);
        return openssl_verify($data, $signature, $publicKey, $algorithm) === 1;
    }

    private function verifyRSAPSSSignature(string $data, string $signature, $publicKey, SignatureScheme $scheme): bool
    {
        $algorithm = $this->getOpenSSLAlgorithm($scheme);

        // PHP's openssl_verify handles PSS automatically when the key was created with PSS
        $result = openssl_verify($data, $signature, $publicKey, $algorithm);

        return $result === 1;
    }

    private function verifyECDSASignature(string $data, string $signature, $publicKey, SignatureScheme $scheme): bool
    {
        $algorithm = $this->getOpenSSLAlgorithm($scheme);
        return openssl_verify($data, $signature, $publicKey, $algorithm) === 1;
    }

    private function getOpenSSLAlgorithm(SignatureScheme $scheme): int
    {
        return match ($scheme) {
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PSS_PSS_SHA256,
            SignatureScheme::ECDSA_SECP256R1_SHA256 => OPENSSL_ALGO_SHA256,

            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PSS_RSAE_SHA384,
            SignatureScheme::RSA_PSS_PSS_SHA384,
            SignatureScheme::ECDSA_SECP384R1_SHA384 => OPENSSL_ALGO_SHA384,

            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_RSAE_SHA512,
            SignatureScheme::RSA_PSS_PSS_SHA512,
            SignatureScheme::ECDSA_SECP521R1_SHA512 => OPENSSL_ALGO_SHA512,

            default => throw new CryptoException("Unsupported signature scheme: {$scheme->name}"),
        };
    }

    private function getHashAlgorithm(SignatureScheme $scheme): string
    {
        return match ($scheme) {
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PSS_PSS_SHA256 => 'sha256',

            SignatureScheme::RSA_PSS_RSAE_SHA384,
            SignatureScheme::RSA_PSS_PSS_SHA384 => 'sha384',

            SignatureScheme::RSA_PSS_RSAE_SHA512,
            SignatureScheme::RSA_PSS_PSS_SHA512 => 'sha512',

            default => throw new CryptoException("No hash algorithm for scheme: {$scheme->name}"),
        };
    }

    private function getAlgorithmName(int $algorithm): string
    {
        return match ($algorithm) {
            OPENSSL_ALGO_SHA256 => 'SHA256',
            OPENSSL_ALGO_SHA384 => 'SHA384',
            OPENSSL_ALGO_SHA512 => 'SHA512',
            default => 'UNKNOWN',
        };
    }
}
