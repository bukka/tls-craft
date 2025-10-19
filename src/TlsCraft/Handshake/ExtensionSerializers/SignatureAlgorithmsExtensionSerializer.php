<?php

namespace Php\TlsCraft\Handshake\ExtensionSerializers;

use Php\TlsCraft\Handshake\Extensions\SignatureAlgorithmsExtension;

class SignatureAlgorithmsExtensionSerializer extends AbstractExtensionSerializer
{
    public function serialize(SignatureAlgorithmsExtension $extension): string
    {
        $algorithmsData = '';
        foreach ($extension->getSignatureAlgorithms() as $algorithm) {
            $algorithmsData .= pack('n', $algorithm->value);
        }

        return $this->packData($algorithmsData);
    }
}
