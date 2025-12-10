<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CryptoException;
use Php\TlsCraft\Logger;

class PrivateKey
{
    private \OpenSSLAsymmetricKey $resource;
    private array $details;

    private function __construct(\OpenSSLAsymmetricKey $resource)
    {
        $this->resource = $resource;

        $details = openssl_pkey_get_details($resource);
        if ($details === false) {
            throw new CryptoException('Failed to get private key details: ' . openssl_error_string());
        }
        $this->details = $details;

        Logger::debug('Private key loaded', [
            'Key type' => $this->getKeyTypeName(),
            'Key size' => $this->details['bits'] ?? 'unknown',
        ]);
    }

    public static function fromPEM(string $pemData, ?string $passphrase = null): self
    {
        Logger::debug('Loading private key from PEM', [
            'PEM length' => strlen($pemData),
            'Has passphrase' => $passphrase !== null,
        ]);

        $key = openssl_pkey_get_private($pemData, $passphrase ?? '');
        if ($key === false) {
            throw new CryptoException('Failed to read private key: ' . openssl_error_string());
        }

        return new self($key);
    }

    public static function fromFile(string $path, ?string $passphrase = null): self
    {
        Logger::debug('Loading private key from file', [
            'Path' => $path,
        ]);

        if (!file_exists($path)) {
            throw new CryptoException("Private key file not found: {$path}");
        }

        $pemData = file_get_contents($path);
        if ($pemData === false) {
            throw new CryptoException("Failed to read private key file: {$path}");
        }

        return self::fromPEM($pemData, $passphrase);
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

    public function getResource(): \OpenSSLAsymmetricKey
    {
        return $this->resource;
    }

    public function matchesCertificate(Certificate $certificate): bool
    {
        return $this->getKeyType() === $certificate->getKeyType();
    }
}
