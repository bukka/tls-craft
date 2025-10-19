<?php

namespace Php\TlsCraft\Handshake\Processors;

use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Handshake\ExtensionType;
use Php\TlsCraft\Handshake\Messages\Certificate;

class CertificateProcessor extends MessageProcessor
{
    public function process(Certificate $message): void
    {
        // Validate certificate request context (should be empty for server cert)
        if (!empty($message->certificateRequestContext)) {
            if (!$this->context->isClient()) {
                throw new ProtocolViolationException('Server Certificate message must have empty certificate_request_context');
            }
            // For client certificates, context should match CertificateRequest
            $this->validateCertificateRequestContext($message->certificateRequestContext);
        }

        // Validate certificate list
        if (empty($message->certificateList)) {
            throw new ProtocolViolationException('Certificate message must contain at least one certificate');
        }

        // Process certificate chain
        $this->processCertificateChain($message->certificateList);

        // Store certificate chain in context
        $this->context->setCertificateChain($message->certificateList);

        // Extract and validate certificate extensions
        $this->processCertificateExtensions($message->certificateList);

        // Perform certificate validation
        $this->validateCertificateChain($message->certificateList);
    }

    private function validateCertificateRequestContext(string $context): void
    {
        $expectedContext = $this->context->getCertificateRequestContext();
        if ($context !== $expectedContext) {
            throw new ProtocolViolationException('Certificate request context mismatch');
        }
    }

    private function processCertificateChain(array $certificateList): void
    {
        foreach ($certificateList as $index => $entry) {
            // Back-compat: allow plain string or the new structured entry
            if (is_string($entry)) {
                $certificateDer = $entry;
                $extensionsRaw  = '';
            } elseif (is_array($entry)) {
                $certificateDer = $entry['certificate'] ?? '';
                $extensionsRaw  = $entry['extensions']  ?? '';
            } else {
                throw new ProtocolViolationException('Invalid certificate list entry');
            }

            if ($certificateDer === '') {
                throw new ProtocolViolationException('Empty certificate in chain');
            }

            $parsedCert = $this->parseX509Certificate($certificateDer);

            if ($index === 0) {
                $this->processEndEntityCertificate($parsedCert, $extensionsRaw);
            } else {
                $this->processIntermediateCertificate($parsedCert, $extensionsRaw);
            }
        }
    }

    private function parseX509Certificate(string $certificateDer): array
    {
        // Detect DER (first byte 0x30 and looks binary) and wrap as PEM
        $isLikelyDer = isset($certificateDer[0]) && ord($certificateDer[0]) === 0x30;
        $pem = $isLikelyDer
            ? $this->derToPem($certificateDer)
            : $certificateDer; // allow already-PEM input

        $certResource = openssl_x509_read($pem);
        if ($certResource === false) {
            throw new ProtocolViolationException('Failed to parse X.509 certificate');
        }

        $certInfo = openssl_x509_parse($certResource);
        if ($certInfo === false) {
            throw new ProtocolViolationException('Failed to parse certificate information');
        }

        $exportedPem = null;
        openssl_x509_export($certResource, $exportedPem);

        return [
            'resource' => $certResource,
            'info'     => $certInfo,
            'pem'      => $exportedPem,
            'der'      => $certificateDer,
        ];
    }

    private function derToPem(string $der): string
    {
        return "-----BEGIN CERTIFICATE-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END CERTIFICATE-----\n";
    }

    private function processEndEntityCertificate(array $parsedCert, string $extensionsRaw): void
    {
        $certInfo = $parsedCert['info'];

        $publicKey = openssl_pkey_get_public($parsedCert['resource']);
        if ($publicKey === false) {
            throw new ProtocolViolationException('Failed to extract public key from certificate');
        }
        $this->context->setPeerPublicKey($publicKey);

        $this->validateCertificatePurpose($certInfo);
        $this->validateCertificateValidity($certInfo);
        $this->validateSubjectAlternativeName($certInfo);

        // Optionally parse $extensionsRaw (OCSP/SCT) in the future.
    }

    private function processIntermediateCertificate(array $parsedCert, string $extensionsRaw): void
    {
        $certInfo = $parsedCert['info'];

        if (!$this->isCACertificate($certInfo)) {
            throw new ProtocolViolationException('Intermediate certificate is not a valid CA certificate');
        }

        $this->validateCertificateValidity($certInfo);
        $this->context->addIntermediateCertificate($parsedCert);
    }

    private function validateCertificatePurpose(array $certInfo): void
    {
        // Check if certificate has the required key usage
        $keyUsage = $certInfo['extensions']['keyUsage'] ?? '';

        if (!$this->context->isClient()) {
            // Server certificate validation
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
            // Client certificate validation
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
        if (!$this->context->isClient()) {
            // Server certificate - validate against requested server name
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

    private function processCertificateExtensions(array $certificateList): void
    {
        foreach ($certificateList as $certEntry) {
            $extensions = $certEntry['extensions'] ?? [];

            foreach ($extensions as $extension) {
                $this->processCertificateExtension($extension);
            }
        }
    }

    private function processCertificateExtension($extension): void
    {
        // Process TLS certificate extensions (different from handshake extensions)
        // These are extensions within the Certificate message itself

        $extensionType = ExtensionType::from($extension->type->value);

        switch ($extensionType) {
            case ExtensionType::STATUS_REQUEST:
                // OCSP stapling
                $this->processOCSPStatus($extension);
                break;

            case ExtensionType::SIGNED_CERTIFICATE_TIMESTAMP:
                // Certificate Transparency
                $this->processSCT($extension);
                break;

            default:
                // Unknown or unhandled extension - ignore or log
                break;
        }
    }

    private function processOCSPStatus($extension): void
    {
        // Process OCSP stapled response
        // This would validate the OCSP response to check certificate revocation status
        // $this->context->setOCSPResponse($extension->data);
    }

    private function processSCT($extension): void
    {
        // Process Signed Certificate Timestamp for Certificate Transparency
        // $this->context->addSCT($extension->data);
    }

    private function validateCertificateChain(array $certificateList): void
    {
        // This is a simplified chain validation
        // In production, you'd want more thorough validation including:
        // - Path building and validation
        // - Revocation checking (CRL/OCSP)
        // - Certificate Transparency verification
        // - Policy constraints validation

        if (count($certificateList) === 1) {
            // Single certificate - might be self-signed or we trust it directly
            $this->validateSingleCertificate($certificateList[0]['certificate']);
        } else {
            // Certificate chain validation
            $this->validateChainSignatures($certificateList);
        }
    }

    private function validateSingleCertificate(string $certificate): void
    {
        // For testing purposes, we might accept self-signed certificates
        // or certificates in a test trust store

        if (!$this->config->isAllowSelfSignedCertificates()) {
            // In production, verify against trusted root CA store
            $this->verifyAgainstTrustStore($certificate);
        }
    }

    private function validateChainSignatures(array $certificateList): void
    {
        $norm = static function($entry): string {
            if (is_string($entry)) return $entry;                  // DER
            if (is_array($entry) && isset($entry['certificate']))  // DER
                return $entry['certificate'];
            throw new ProtocolViolationException('Invalid certificate entry');
        };

        for ($i = 0; $i < count($certificateList) - 1; ++$i) {
            $certDer   = $norm($certificateList[$i]);
            $issuerDer = $norm($certificateList[$i + 1]);

            if (!$this->verifyCertificateSignature($certDer, $issuerDer)) {
                throw new ProtocolViolationException("Certificate chain validation failed at position {$i}");
            }
        }

        $rootDer = $norm($certificateList[count($certificateList) - 1]);
        $this->verifyAgainstTrustStore($rootDer);
    }

    private function verifyCertificateSignature(string $certDer, string $issuerDer): bool
    {
        $cert  = openssl_x509_read($this->derToPemIfNeeded($certDer));
        $issuer = openssl_x509_read($this->derToPemIfNeeded($issuerDer));
        if ($cert === false || $issuer === false) return false;

        $issuerPublicKey = openssl_pkey_get_public($issuer);
        if ($issuerPublicKey === false) return false;

        return openssl_x509_verify($cert, $issuerPublicKey) === 1;
    }

    private function derToPemIfNeeded(string $maybeDer): string
    {
        return (isset($maybeDer[0]) && ord($maybeDer[0]) === 0x30)
            ? $this->derToPem($maybeDer)
            : $maybeDer; // already PEM
    }

    private function verifyAgainstTrustStore(string $certificate): void
    {
        // This would verify the certificate against a trusted CA store
        // For testing framework, we might skip this or use a test CA store

        if ($this->config->isRequireTrustedCertificates()) {
            // Implement trust store verification
            throw new ProtocolViolationException('Certificate trust store verification not implemented');
        }
    }
}
