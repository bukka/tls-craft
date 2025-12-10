<?php

namespace Php\TlsCraft\Handshake\Processors;

use Php\TlsCraft\Crypto\Certificate;
use Php\TlsCraft\Crypto\CertificateChain;
use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Handshake\Messages\CertificateMessage;
use Php\TlsCraft\Logger;

class CertificateProcessor extends MessageProcessor
{
    public function process(CertificateMessage $message): void
    {
        Logger::debug('Processing Certificate message', [
            'Context length' => strlen($message->certificateRequestContext),
            'Chain length' => $message->certificateChain->getLength(),
        ]);

        // Validate certificate request context (should be empty for server cert)
        if (!empty($message->certificateRequestContext)) {
            if (!$this->context->isClient()) {
                throw new ProtocolViolationException('Server Certificate message must have empty certificate_request_context');
            }
            // For client certificates, context should match CertificateRequest
            $this->validateCertificateRequestContext($message->certificateRequestContext);
        }

        // Validate certificate list
        if ($message->certificateChain->getLength() === 0) {
            throw new ProtocolViolationException('Certificate message must contain at least one certificate');
        }

        // Store certificate chain in context
        $this->context->setCertificateChain($message->certificateChain);

        // Process and validate certificate chain
        $this->processCertificateChain($message->certificateChain);

        // Perform certificate validation
        $this->validateCertificateChain($message->certificateChain);
    }

    private function validateCertificateRequestContext(string $context): void
    {
        $expectedContext = $this->context->getCertificateRequestContext();
        if ($context !== $expectedContext) {
            throw new ProtocolViolationException('Certificate request context mismatch');
        }
    }

    private function processCertificateChain(CertificateChain $certificateChain): void
    {
        $certificates = $certificateChain->getCertificates();

        foreach ($certificates as $index => $certificate) {
            $certResource = $certificate->getResource();
            $certInfo = openssl_x509_parse($certResource);

            if ($certInfo === false) {
                throw new ProtocolViolationException('Failed to parse certificate information');
            }

            if ($index === 0) {
                $this->processEndEntityCertificate($certificate, $certInfo);
            } else {
                $this->processIntermediateCertificate($certificate, $certInfo);
            }
        }
    }

    private function processEndEntityCertificate(Certificate $certificate, array $certInfo): void
    {
        $publicKey = $certificate->getPublicKey();
        $this->context->setPeerPublicKey($publicKey);

        Logger::debug('Processing end-entity certificate', [
            'Subject' => $certInfo['subject']['CN'] ?? 'unknown',
            'Key type' => $certificate->getKeyTypeName(),
        ]);

        $this->validateCertificatePurpose($certInfo);
        $this->validateCertificateValidity($certInfo);
        $this->validateSubjectAlternativeName($certInfo);
    }

    private function processIntermediateCertificate(Certificate $certificate, array $certInfo): void
    {
        Logger::debug('Processing intermediate certificate', [
            'Subject' => $certInfo['subject']['CN'] ?? 'unknown',
        ]);

        if (!$this->isCACertificate($certInfo)) {
            throw new ProtocolViolationException('Intermediate certificate is not a valid CA certificate');
        }

        $this->validateCertificateValidity($certInfo);
    }

    private function validateCertificatePurpose(array $certInfo): void
    {
        // Skip validation if disabled or for self-signed certificates
        if (!$this->config->isValidateCertificatePurpose() || $this->config->isAllowSelfSignedCertificates()) {
            return;
        }

        // Check if certificate has the required key usage
        $keyUsage = $certInfo['extensions']['keyUsage'] ?? '';

        if ($this->context->isClient()) {
            // We are client - validating server certificate
            if (!str_contains($keyUsage, 'Digital Signature')
                && !str_contains($keyUsage, 'Key Agreement')) {
                throw new ProtocolViolationException('Server certificate missing required key usage');
            }

            // Check Extended Key Usage
            $extKeyUsage = $certInfo['extensions']['extendedKeyUsage'] ?? '';
            if (!str_contains($extKeyUsage, 'TLS Web Server Authentication')) {
                throw new ProtocolViolationException('Server certificate missing serverAuth extended key usage');
            }
        } else {
            // We are server - validating client certificate
            if (!str_contains($keyUsage, 'Digital Signature')) {
                throw new ProtocolViolationException('Client certificate missing Digital Signature key usage');
            }

            $extKeyUsage = $certInfo['extensions']['extendedKeyUsage'] ?? '';
            if (!str_contains($extKeyUsage, 'TLS Web Client Authentication')) {
                throw new ProtocolViolationException('Client certificate missing clientAuth extended key usage');
            }
        }
    }

    private function validateCertificateValidity(array $certInfo): void
    {
        // Skip validation if disabled
        if (!$this->config->isValidateCertificateExpiry()) {
            return;
        }

        $now = time();
        $validFrom = $certInfo['validFrom_time_t'];
        $validTo = $certInfo['validTo_time_t'];

        if ($now < $validFrom) {
            throw new ProtocolViolationException('Certificate is not yet valid (valid from: '.date('Y-m-d H:i:s', $validFrom).')');
        }

        if ($now > $validTo) {
            throw new ProtocolViolationException('Certificate has expired (valid to: '.date('Y-m-d H:i:s', $validTo).')');
        }
    }

    private function validateSubjectAlternativeName(array $certInfo): void
    {
        // Skip validation if disabled
        if (!$this->config->isValidateHostname()) {
            return;
        }

        if ($this->context->isClient()) {
            // We are client - validate server certificate against requested server name
            $requestedServerName = $this->context->getRequestedServerName();
            if ($requestedServerName) {
                $this->validateServerName($certInfo, $requestedServerName);
            }
        }
    }

    private function validateServerName(array $certInfo, string $requestedName): void
    {
        $san = $certInfo['extensions']['subjectAltName'] ?? '';
        $commonName = $certInfo['subject']['CN'] ?? '';

        $validNames = [];

        // Parse SAN extension
        if ($san) {
            $sanEntries = explode(', ', $san);
            foreach ($sanEntries as $entry) {
                if (str_starts_with($entry, 'DNS:')) {
                    $validNames[] = substr($entry, 4);
                }
            }
        }

        // Add common name if no SAN DNS names
        if (empty($validNames) && $commonName) {
            $validNames[] = $commonName;
        }

        // Check if requested name matches any valid name
        foreach ($validNames as $validName) {
            if ($this->matchesHostname($requestedName, $validName)) {
                return; // Match found
            }
        }

        throw new ProtocolViolationException("Certificate does not match requested server name: {$requestedName}");
    }

    private function matchesHostname(string $hostname, string $pattern): bool
    {
        // Simple hostname matching (supports wildcards)
        if ($pattern === $hostname) {
            return true;
        }

        // Wildcard matching (*.example.com)
        if (str_starts_with($pattern, '*.')) {
            $domain = substr($pattern, 2);
            return str_ends_with($hostname, '.'.$domain);
        }

        return false;
    }

    private function isCACertificate(array $certInfo): bool
    {
        $basicConstraints = $certInfo['extensions']['basicConstraints'] ?? '';
        return str_contains($basicConstraints, 'CA:TRUE');
    }

    private function validateCertificateChain(CertificateChain $certificateChain): void
    {
        $certificates = $certificateChain->getCertificates();

        if (count($certificates) === 1) {
            $this->validateSingleCertificate($certificateChain->getLeafCertificate());
        } else {
            $this->validateChainSignatures($certificates);
        }
    }

    private function validateSingleCertificate(Certificate $certificate): void
    {
        if (!$this->config->isAllowSelfSignedCertificates()) {
            $this->verifyAgainstTrustStore($certificate);
        }
    }

    private function validateChainSignatures(array $certificates): void
    {
        for ($i = 0; $i < count($certificates) - 1; ++$i) {
            $cert = $certificates[$i];
            $issuer = $certificates[$i + 1];

            if (!$this->verifyCertificateSignature($cert, $issuer)) {
                throw new ProtocolViolationException("Certificate chain validation failed at position {$i}");
            }
        }

        $rootCert = $certificates[count($certificates) - 1];
        $this->verifyAgainstTrustStore($rootCert);
    }

    private function verifyCertificateSignature(Certificate $cert, Certificate $issuer): bool
    {
        $certResource = $cert->getResource();
        $issuerPublicKey = $issuer->getPublicKey();

        return openssl_x509_verify($certResource, $issuerPublicKey) === 1;
    }

    private function verifyAgainstTrustStore(Certificate $certificate): void
    {
        if (!$this->config->isRequireTrustedCertificates()) {
            return;
        }

        $caPath = $this->config->getCustomCaPath();
        $caFile = $this->config->getCustomCaFile();

        if ($caPath === null && $caFile === null) {
            $this->verifyWithSystemCaBundle($certificate);
        } else {
            $this->verifyWithCustomCa($certificate, $caPath, $caFile);
        }
    }

    private function verifyWithSystemCaBundle(Certificate $certificate): void
    {
        $certResource = $certificate->getResource();

        $result = openssl_x509_checkpurpose($certResource, X509_PURPOSE_SSL_CLIENT, []);
        if ($result !== true) {
            throw new ProtocolViolationException('Certificate verification failed: not trusted by system CA bundle');
        }
    }

    private function verifyWithCustomCa(Certificate $certificate, ?string $caPath, ?string $caFile): void
    {
        $certResource = $certificate->getResource();

        $caList = [];
        if ($caPath !== null) {
            $caList[] = $caPath;
        }
        if ($caFile !== null) {
            $caList[] = $caFile;
        }

        $purpose = $this->context->isClient() ? X509_PURPOSE_SSL_SERVER : X509_PURPOSE_SSL_CLIENT;
        $result = openssl_x509_checkpurpose($certResource, $purpose, $caList);

        if ($result !== true) {
            throw new ProtocolViolationException('Certificate verification failed: not trusted by custom CA');
        }
    }
}
