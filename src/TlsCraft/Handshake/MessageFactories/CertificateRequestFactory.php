<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Handshake\Extensions\SignatureAlgorithmsExtension;
use Php\TlsCraft\Handshake\Messages\CertificateRequestMessage;

class CertificateRequestFactory extends AbstractMessageFactory
{
    public function create(): CertificateRequestMessage
    {
        // Generate certificate request context (can be empty or contain opaque data)
        $certificateRequestContext = $this->context->getCryptoFactory()
            ->createRandomGenerator()
            ->generateBytes(32); // 32 bytes of random context

        // Create signature_algorithms extension (mandatory for TLS 1.3)
        $signatureAlgorithms = $this->config->getSignatureAlgorithms();
        $extensions = [
            new SignatureAlgorithmsExtension($signatureAlgorithms),
        ];

        // TODO: Add certificate_authorities extension if needed
        // This would list acceptable certificate authorities for the client

        return new CertificateRequestMessage($certificateRequestContext, $extensions);
    }
}
