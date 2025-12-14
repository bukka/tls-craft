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
        $signatureAlgorithms = $this->extractSignatureAlgorithms($message);
        if (empty($signatureAlgorithms)) {
            throw new ProtocolViolationException('CertificateRequest must include signature_algorithms extension');
        }

        $this->context->setServerSignatureAlgorithms($signatureAlgorithms);

        Logger::debug('CertificateRequest processed', [
            'Signature algorithms' => array_map(fn ($s) => $s->name, $signatureAlgorithms),
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
}
