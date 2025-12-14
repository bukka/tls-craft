<?php

namespace Php\TlsCraft\Handshake\MessageSerializers;

use Php\TlsCraft\Handshake\Messages\CertificateRequestMessage;

class CertificateRequestSerializer extends AbstractMessageSerializer
{
    public function serialize(CertificateRequestMessage $message): string
    {
        $encoded = '';

        // Certificate request context (1-byte length prefix)
        $contextLength = strlen($message->certificateRequestContext);
        $encoded .= chr($contextLength);
        $encoded .= $message->certificateRequestContext;

        // Extensions (2-byte length prefix)
        $encoded .= $this->extensionFactory->encodeExtensionList($message->extensions);

        return $encoded;
    }
}
