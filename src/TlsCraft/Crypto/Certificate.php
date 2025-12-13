<?php

namespace Php\TlsCraft\Crypto;

use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use Php\TlsCraft\Exceptions\CryptoException;
use Php\TlsCraft\Logger;

class Certificate
{
    private OpenSSLCertificate $resource;
    private OpenSSLAsymmetricKey $publicKey;
    private array $details;
    private string $derData;

    private function __construct(
        OpenSSLCertificate $resource,
        string $derData,
    ) {
        $this->resource = $resource;
        $this->derData = $derData;

        $publicKey = openssl_pkey_get_public($resource);
        if ($publicKey === false) {
            throw new CryptoException('Failed to extract public key from certificate: '.openssl_error_string());
        }
        $this->publicKey = $publicKey;

        $details = openssl_pkey_get_details($publicKey);
        if ($details === false) {
            throw new CryptoException('Failed to get public key details: '.openssl_error_string());
        }
        $this->details = $details;

        Logger::debug('Certificate loaded', [
            'Key type' => $this->getKeyTypeName(),
            'Key size' => $this->details['bits'] ?? 'unknown',
            'DER length' => strlen($derData),
        ]);
    }

    public static function fromPEM(string $pemData): self
    {
        $cert = openssl_x509_read($pemData);
        if ($cert === false) {
            throw new CryptoException('Failed to read certificate: '.openssl_error_string());
        }

        // Export to PEM without text
        if (!openssl_x509_export($cert, $cleanPem, true)) {
            throw new CryptoException('Failed to export certificate: '.openssl_error_string());
        }

        // Convert PEM to DER
        $base64Data = preg_replace(
            ['/-----BEGIN CERTIFICATE-----/', '/-----END CERTIFICATE-----/', '/\s+/'],
            '',
            $cleanPem,
        );

        $derData = base64_decode($base64Data);
        if ($derData === false || empty($derData)) {
            throw new CryptoException('Failed to decode certificate to DER format');
        }

        return new self($cert, $derData);
    }

    public function toDER(): string
    {
        return $this->derData;
    }

    public function getKeyType(): int
    {
        return $this->details['type'];
    }

    public function getKeyTypeName(): string
    {
        return match ($this->details['type']) {
            OPENSSL_KEYTYPE_RSA => 'RSA',
            OPENSSL_KEYTYPE_EC => 'EC',
            OPENSSL_KEYTYPE_ED25519 => 'Ed25519',
            OPENSSL_KEYTYPE_ED448 => 'Ed448',
            default => 'Unknown',
        };
    }

    public function getKeySize(): int
    {
        return $this->details['bits'] ?? 0;
    }

    public function getSupportedSignatureSchemes(): array
    {
        $keyType = $this->getKeyType();

        Logger::debug('Getting supported signature schemes for certificate', [
            'Key type' => $this->getKeyTypeName(),
        ]);

        if ($keyType === OPENSSL_KEYTYPE_EC) {
            // For EC keys, only the signature scheme matching the certificate's curve is supported
            $curve = $this->getECCurveName();

            Logger::debug('EC certificate curve detected', [
                'Curve' => $curve,
            ]);

            return match ($curve) {
                'prime256v1', 'secp256r1', 'P-256' => [SignatureScheme::ECDSA_SECP256R1_SHA256],
                'secp384r1', 'P-384' => [SignatureScheme::ECDSA_SECP384R1_SHA384],
                'secp521r1', 'P-521' => [SignatureScheme::ECDSA_SECP521R1_SHA512],
                default => [],
            };
        }

        return match ($keyType) {
            OPENSSL_KEYTYPE_RSA => [
                SignatureScheme::RSA_PSS_RSAE_SHA256,
                SignatureScheme::RSA_PSS_RSAE_SHA384,
                SignatureScheme::RSA_PSS_RSAE_SHA512,
                SignatureScheme::RSA_PSS_PSS_SHA256,
                SignatureScheme::RSA_PSS_PSS_SHA384,
                SignatureScheme::RSA_PSS_PSS_SHA512,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
            ],
            OPENSSL_KEYTYPE_ED25519 => [
                SignatureScheme::ED25519,
            ],
            OPENSSL_KEYTYPE_ED448 => [
                SignatureScheme::ED448,
            ],
            default => [],
        };
    }

    private function getECCurveName(): string
    {
        if ($this->getKeyType() !== OPENSSL_KEYTYPE_EC) {
            return '';
        }

        // The curve name is stored in the 'ec' array under 'curve_name'
        return $this->details['ec']['curve_name'] ?? '';
    }

    public function getPublicKey(): OpenSSLAsymmetricKey
    {
        return $this->publicKey;
    }

    public function getResource(): OpenSSLCertificate
    {
        return $this->resource;
    }
}
