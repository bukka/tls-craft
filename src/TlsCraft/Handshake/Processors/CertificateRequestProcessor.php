<?php

namespace Php\TlsCraft\Handshake\Processors;

use Php\TlsCraft\Crypto\SignatureScheme;
use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Handshake\Extensions\SignatureAlgorithmsExtension;
use Php\TlsCraft\Handshake\Messages\CertificateRequestMessage;
use Php\TlsCraft\Logger;

class CertificateRequestProcessor extends MessageProcessor
{
    public function process(CertificateRequestMessage $message): void
    {
        Logger::debug('Processing CertificateRequest message', [
            'Context length' => strlen($message->certificateRequestContext),
            'Extensions count' => count($message->extensions),
        ]);

        // Client should only receive CertificateRequest
        if (!$this->context->isClient()) {
            throw new ProtocolViolationException('Server should not receive CertificateRequest message');
        }

        // Store certificate request context for later use in client Certificate message
        $this->context->setCertificateRequestContext($message->certificateRequestContext);

        // Process signature_algorithms extension (mandatory in TLS 1.3)
        $serverSignatureAlgorithms = $this->extractSignatureAlgorithms($message);
        if (empty($serverSignatureAlgorithms)) {
            throw new ProtocolViolationException('CertificateRequest must include signature_algorithms extension');
        }

        $this->context->setServerSignatureAlgorithms($serverSignatureAlgorithms);

        // Negotiate signature scheme for client's CertificateVerify
        $selectedScheme = $this->negotiateSignatureScheme($serverSignatureAlgorithms);
        if (!$selectedScheme) {
            throw new ProtocolViolationException('No compatible signature algorithm found for client certificate');
        }

        $this->context->setNegotiatedSignatureScheme($selectedScheme);

        Logger::debug('CertificateRequest processed', [
            'Signature algorithms' => array_map(fn ($s) => $s->name, $serverSignatureAlgorithms),
            'Selected scheme' => $selectedScheme->name,
            'Context' => bin2hex($message->certificateRequestContext),
        ]);
    }

    /**
     * Extract signature algorithms from extensions
     *
     * @return SignatureScheme[]
     */
    private function extractSignatureAlgorithms(CertificateRequestMessage $message): array
    {
        foreach ($message->extensions as $extension) {
            if ($extension instanceof SignatureAlgorithmsExtension) {
                return $extension->getSignatureAlgorithms();
            }
        }

        return [];
    }

    /**
     * Negotiate signature scheme between server's requirements and client certificate
     *
     * @param SignatureScheme[] $serverSignatureAlgorithms
     */
    private function negotiateSignatureScheme(array $serverSignatureAlgorithms): ?SignatureScheme
    {
        $certificateChain = $this->context->getClientCertificateChain();
        if (!$certificateChain) {
            Logger::error('No client certificate configured for mutual TLS');

            return null;
        }

        // Get algorithms supported by the client certificate
        $certificateSchemes = $certificateChain->getSupportedSignatureSchemes();

        Logger::debug('Negotiating client signature scheme', [
            'certificate_key_type' => $certificateChain->getKeyTypeName(),
            'certificate_schemes' => array_map(fn ($s) => $s->name, $certificateSchemes),
            'server_requested_schemes' => array_map(fn ($s) => $s->name, $serverSignatureAlgorithms),
        ]);

        // Find first match: must be supported by both client certificate and server
        // Priority: server's preference (order in CertificateRequest)
        foreach ($serverSignatureAlgorithms as $serverScheme) {
            foreach ($certificateSchemes as $certScheme) {
                if ($serverScheme === $certScheme) {
                    Logger::debug('Client signature scheme selected', [
                        'scheme' => $serverScheme->name,
                    ]);

                    return $serverScheme;
                }
            }
        }

        Logger::error('No matching signature scheme found between server request and client certificate', [
            'certificate_schemes' => array_map(fn ($s) => $s->name, $certificateSchemes),
            'server_schemes' => array_map(fn ($s) => $s->name, $serverSignatureAlgorithms),
        ]);

        return null;
    }
}
