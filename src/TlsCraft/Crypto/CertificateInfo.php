<?php

namespace Php\TlsCraft\Crypto;

use OpenSSLCertificate;
use Php\TlsCraft\Exceptions\CryptoException;

class CertificateInfo
{
    private array $parsedData;

    private function __construct(array $parsedData)
    {
        $this->parsedData = $parsedData;
    }

    public static function fromCertificate(Certificate $certificate): self
    {
        return self::fromResource($certificate->getResource());
    }

    public static function fromResource(OpenSSLCertificate $certResource): self
    {
        $parsedData = openssl_x509_parse($certResource);

        if ($parsedData === false) {
            throw new CryptoException('Failed to parse certificate information: '.openssl_error_string());
        }

        return new self($parsedData);
    }

    public function getSubjectCommonName(): ?string
    {
        return $this->parsedData['subject']['CN'] ?? null;
    }

    public function getIssuerCommonName(): ?string
    {
        return $this->parsedData['issuer']['CN'] ?? null;
    }

    public function getKeyUsage(): string
    {
        return $this->parsedData['extensions']['keyUsage'] ?? '';
    }

    public function getExtendedKeyUsage(): string
    {
        return $this->parsedData['extensions']['extendedKeyUsage'] ?? '';
    }

    public function getSubjectAlternativeName(): string
    {
        return $this->parsedData['extensions']['subjectAltName'] ?? '';
    }

    public function getBasicConstraints(): string
    {
        return $this->parsedData['extensions']['basicConstraints'] ?? '';
    }

    public function getValidFromTimestamp(): int
    {
        return $this->parsedData['validFrom_time_t'];
    }

    public function getValidToTimestamp(): int
    {
        return $this->parsedData['validTo_time_t'];
    }

    public function isCA(): bool
    {
        return str_contains($this->getBasicConstraints(), 'CA:TRUE');
    }

    public function hasKeyUsage(string $usage): bool
    {
        return str_contains($this->getKeyUsage(), $usage);
    }

    public function hasExtendedKeyUsage(string $usage): bool
    {
        return str_contains($this->getExtendedKeyUsage(), $usage);
    }

    /**
     * Get list of DNS names from SAN extension
     *
     * @return string[]
     */
    public function getDnsNames(): array
    {
        $san = $this->getSubjectAlternativeName();
        $dnsNames = [];

        if ($san) {
            $sanEntries = explode(', ', $san);
            foreach ($sanEntries as $entry) {
                if (str_starts_with($entry, 'DNS:')) {
                    $dnsNames[] = substr($entry, 4);
                }
            }
        }

        // Add common name if no SAN DNS names
        if (empty($dnsNames)) {
            $cn = $this->getSubjectCommonName();
            if ($cn) {
                $dnsNames[] = $cn;
            }
        }

        return $dnsNames;
    }

    /**
     * Get the raw parsed data array
     */
    public function toArray(): array
    {
        return $this->parsedData;
    }
}
