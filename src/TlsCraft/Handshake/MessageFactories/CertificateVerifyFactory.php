<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\Messages\CertificateVerifyMessage;

class CertificateVerifyFactory extends AbstractMessageFactory
{
    public function create(string $signature): CertificateVerifyMessage
    {
        $signatureScheme = $this->context->getNegotiatedSignatureScheme();
        if ($signatureScheme === null) {
            throw new CraftException('No signature scheme negotiated');
        }

        return new CertificateVerifyMessage($signatureScheme, $signature);
    }
}
