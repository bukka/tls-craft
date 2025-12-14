<?php

namespace Php\TlsCraft\Handshake\Processors;

use Php\TlsCraft\Crypto\Certificate;
use Php\TlsCraft\Crypto\CertificateChain;
use Php\TlsCraft\Crypto\CertificateInfo;
use Php\TlsCraft\Crypto\CertificateVerifier;
use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Handshake\Messages\CertificateMessage;
use Php\TlsCraft\Logger;

class CertificateProcessor extends MessageProcessor
{
    private CertificateVerifier $verifier;

    protected function initialize(): void
    {
        $this->verifier = $this->context->getCryptoFactory()->createCertificateVerifier();
    }

    public function process(CertificateMessage $message): void
    {
        // Initialize verifier if needed
        if (!isset($this->verifier)) {
            $this->initialize();
        }

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
            $certInfo = CertificateInfo::fromCertificate($certificate);

            if ($index === 0) {
                $this->processEndEntityCertificate($certificate, $certInfo);
            } else {
                $this->processIntermediateCertificate($certificate, $certInfo);
            }
        }
    }

    private function processEndEntityCertificate(Certificate $certificate, CertificateInfo $certInfo): void
    {
        $publicKey = $certificate->getPublicKey();
        $this->context->setPeerPublicKey($publicKey);

        Logger::debug('Processing end-entity certificate', [
            'Subject' => $certInfo->getSubjectCommonName() ?? 'unknown',
            'Key type' => $certificate->getKeyTypeName(),
        ]);

        $this->validateCertificatePurpose($certInfo);
        $this->validateCertificateValidity($certInfo);
        $this->validateSubjectAlternativeName($certInfo);
    }

    private function processIntermediateCertificate(Certificate $certificate, CertificateInfo $certInfo): void
    {
        Logger::debug('Processing intermediate certificate', [
            'Subject' => $certInfo->getSubjectCommonName() ?? 'unknown',
        ]);

        if (!$certInfo->isCA()) {
            throw new ProtocolViolationException('Intermediate certificate is not a valid CA certificate');
        }

        $this->validateCertificateValidity($certInfo);
    }

    private function validateCertificatePurpose(CertificateInfo $certInfo): void
    {
        // Skip validation if disabled or for self-signed certificates
        if (!$this->config->isValidateCertificatePurpose() || $this->config->isAllowSelfSignedCertificates()) {
            Logger::debug('Skipping certificate purpose validation');

            return;
        }

        Logger::debug('Validating certificate purpose', [
            'Is client' => $this->context->isClient(),
            'Key usage' => $certInfo->getKeyUsage(),
            'Extended key usage' => $certInfo->getExtendedKeyUsage(),
        ]);

        if ($this->context->isClient()) {
            // We are client - validating server certificate
            if (!$certInfo->hasKeyUsage('Digital Signature')
                && !$certInfo->hasKeyUsage('Key Agreement')) {
                throw new ProtocolViolationException('Server certificate missing required key usage');
            }

            if (!$certInfo->hasExtendedKeyUsage('TLS Web Server Authentication')) {
                throw new ProtocolViolationException('Server certificate missing serverAuth extended key usage');
            }
        } else {
            // We are server - validating client certificate
            if (!$certInfo->hasKeyUsage('Digital Signature')) {
                throw new ProtocolViolationException('Client certificate missing Digital Signature key usage');
            }

            if (!$certInfo->hasExtendedKeyUsage('TLS Web Client Authentication')) {
                throw new ProtocolViolationException('Client certificate missing clientAuth extended key usage');
            }
        }

        Logger::debug('Certificate purpose validation passed');
    }

    private function validateCertificateValidity(CertificateInfo $certInfo): void
    {
        // Skip validation if disabled
        if (!$this->config->isValidateCertificateExpiry()) {
            Logger::debug('Skipping certificate expiry validation');

            return;
        }

        $now = time();
        $validFrom = $certInfo->getValidFromTimestamp();
        $validTo = $certInfo->getValidToTimestamp();

        Logger::debug('Validating certificate validity period', [
            'Valid from' => date('Y-m-d H:i:s', $validFrom),
            'Valid to' => date('Y-m-d H:i:s', $validTo),
            'Current time' => date('Y-m-d H:i:s', $now),
        ]);

        if ($now < $validFrom) {
            throw new ProtocolViolationException('Certificate is not yet valid (valid from: '.date('Y-m-d H:i:s', $validFrom).')');
        }

        if ($now > $validTo) {
            throw new ProtocolViolationException('Certificate has expired (valid to: '.date('Y-m-d H:i:s', $validTo).')');
        }

        Logger::debug('Certificate validity period check passed');
    }

    private function validateSubjectAlternativeName(CertificateInfo $certInfo): void
    {
        // Skip validation if disabled
        if (!$this->config->isValidateHostname()) {
            Logger::debug('Skipping hostname validation');

            return;
        }

        if ($this->context->isClient()) {
            // We are client - validate server certificate against requested server name
            $requestedServerName = $this->context->getRequestedServerName();
            if ($requestedServerName) {
                $this->validateHostname($certInfo, $requestedServerName);
            }
        }
    }

    private function validateHostname(CertificateInfo $certInfo, string $requestedName): void
    {
        Logger::debug('Validating hostname', [
            'Requested name' => $requestedName,
        ]);

        $validNames = $certInfo->getDnsNames();

        Logger::debug('Valid names for hostname matching', [
            'Valid names' => $validNames,
        ]);

        // Check if requested name matches any valid name
        foreach ($validNames as $validName) {
            if ($this->verifier->matchesHostname($requestedName, $validName)) {
                Logger::debug('Hostname matched', [
                    'Requested' => $requestedName,
                    'Matched against' => $validName,
                ]);

                return; // Match found
            }
        }

        throw new ProtocolViolationException("Certificate does not match requested server name: {$requestedName}");
    }

    private function validateCertificateChain(CertificateChain $certificateChain): void
    {
        $certificates = $certificateChain->getCertificates();

        if (count($certificates) === 1) {
            $this->validateSingleCertificate($certificateChain->getLeafCertificate());
        } else {
            $this->validateChainSignatures($certificates);
            $rootCert = $certificates[count($certificates) - 1];
            $this->verifyAgainstTrustStore($rootCert);
        }
    }

    private function validateSingleCertificate(Certificate $certificate): void
    {
        if (!$this->config->isAllowSelfSignedCertificates()) {
            $this->verifyAgainstTrustStore($certificate);
        } else {
            Logger::debug('Allowing self-signed certificate');
        }
    }

    private function validateChainSignatures(array $certificates): void
    {
        for ($i = 0; $i < count($certificates) - 1; ++$i) {
            $cert = $certificates[$i];
            $issuer = $certificates[$i + 1];

            if (!$this->verifier->verifyCertificateSignature($cert, $issuer)) {
                throw new ProtocolViolationException("Certificate chain validation failed at position {$i}");
            }
        }
    }

    private function verifyAgainstTrustStore(Certificate $certificate): void
    {
        if (!$this->config->isRequireTrustedCertificates()) {
            Logger::debug('Skipping trust store verification (not required)');

            return;
        }

        $caPath = $this->config->getCustomCaPath();
        $caFile = $this->config->getCustomCaFile();

        if ($caPath === null && $caFile === null) {
            $this->verifier->verifyWithSystemCaBundle($certificate, $this->context->isClient());
        } else {
            $this->verifier->verifyWithCustomCa($certificate, $this->context->isClient(), $caPath, $caFile);
        }
    }
}
