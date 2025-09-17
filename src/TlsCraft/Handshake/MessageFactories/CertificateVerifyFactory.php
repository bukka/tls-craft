<?php

namespace Php\TlsCraft\Messages\Factories;

use Php\TlsCraft\Messages\CertificateVerify;
use Php\TlsCraft\Exceptions\CraftException;

class CertificateVerifyFactory extends AbstractMessageFactory
{
    public function create(string $signature): CertificateVerify
    {
        $signatureScheme = $this->context->getNegotiatedSignatureScheme();
        if ($signatureScheme === null) {
            throw new CraftException("No signature scheme negotiated");
        }

        return new CertificateVerify($signatureScheme, $signature);
    }
}
