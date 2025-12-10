<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CryptoException;
use Php\TlsCraft\Logger;

class CertificateChain
{
    /** @var Certificate[] */
    private array $certificates;

    /**
     * @param Certificate[] $certificates
     */
    private function __construct(array $certificates)
    {
        if (empty($certificates)) {
            throw new CryptoException('Certificate chain cannot be empty');
        }

        $this->certificates = $certificates;

        Logger::debug('Certificate chain created', [
            'Chain length' => count($certificates),
            'Leaf key type' => $certificates[0]->getKeyTypeName(),
        ]);
    }

    /**
     * Create chain from a single certificate file
     */
    public static function fromFile(string $path): self
    {
        Logger::debug('Loading certificate chain from file', [
            'Path' => $path,
        ]);

        if (!file_exists($path)) {
            throw new CryptoException("Certificate file not found: {$path}");
        }

        $pemData = file_get_contents($path);
        if ($pemData === false) {
            throw new CryptoException("Failed to read certificate file: {$path}");
        }

        return self::fromPEM($pemData);
    }

    /**
     * Create chain from PEM data (can contain multiple certificates)
     */
    public static function fromPEM(string $pemData): self
    {
        Logger::debug('Loading certificate chain from PEM', [
            'PEM length' => strlen($pemData),
        ]);

        // Split PEM data into individual certificates
        $pattern = '/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s';
        preg_match_all($pattern, $pemData, $matches);

        if (empty($matches[0])) {
            throw new CryptoException('No certificates found in PEM data');
        }

        $certificates = [];
        foreach ($matches[0] as $certPem) {
            $certificates[] = Certificate::fromPEM($certPem);
        }

        Logger::debug('Certificates parsed from PEM', [
            'Count' => count($certificates),
        ]);

        return new self($certificates);
    }

    /**
     * Create chain from array of Certificate objects
     *
     * @param Certificate[] $certificates
     */
    public static function fromCertificates(array $certificates): self
    {
        return new self($certificates);
    }

    /**
     * Get the leaf certificate (end-entity certificate)
     * This is the first certificate in the chain
     */
    public function getLeafCertificate(): Certificate
    {
        return $this->certificates[0];
    }

    /**
     * Get all certificates in the chain
     *
     * @return Certificate[]
     */
    public function getCertificates(): array
    {
        return $this->certificates;
    }

    /**
     * Get the number of certificates in the chain
     */
    public function getLength(): int
    {
        return count($this->certificates);
    }

    /**
     * Convert entire chain to DER format for TLS Certificate message
     * Returns array of DER-encoded certificates
     *
     * @return string[]
     */
    public function toDERArray(): array
    {
        $derCerts = [];
        foreach ($this->certificates as $cert) {
            $derCerts[] = $cert->toDER();
        }

        Logger::debug('Certificate chain converted to DER array', [
            'Certificates' => count($derCerts),
            'Total size' => array_sum(array_map('strlen', $derCerts)),
        ]);

        return $derCerts;
    }

    /**
     * Get supported signature schemes based on the leaf certificate
     *
     * @return SignatureScheme[]
     */
    public function getSupportedSignatureSchemes(): array
    {
        return $this->getLeafCertificate()->getSupportedSignatureSchemes();
    }

    /**
     * Get the key type of the leaf certificate
     */
    public function getKeyType(): int
    {
        return $this->getLeafCertificate()->getKeyType();
    }

    /**
     * Get the key type name of the leaf certificate
     */
    public function getKeyTypeName(): string
    {
        return $this->getLeafCertificate()->getKeyTypeName();
    }
}
