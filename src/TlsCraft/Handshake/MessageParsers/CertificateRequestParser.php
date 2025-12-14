<?php

namespace Php\TlsCraft\Handshake\MessageParsers;

use Php\TlsCraft\Handshake\Messages\CertificateRequestMessage;
use Php\TlsCraft\Protocol\HandshakeType;

class CertificateRequestParser extends AbstractMessageParser
{
    public function parse(string $data): CertificateRequestMessage
    {
        $payload = $this->parseHandshake($data, HandshakeType::CERTIFICATE_REQUEST);

        $offset = 0;

        // Certificate request context (1-byte length prefix)
        $contextLength = ord($payload[$offset]);
        ++$offset;
        $certificateRequestContext = substr($payload, $offset, $contextLength);
        $offset += $contextLength;

        // Extensions (2-byte length prefix)
        $extensions = $this->extensionFactory->decodeExtensionList($payload, $offset);

        return new CertificateRequestMessage($certificateRequestContext, $extensions);
    }
}
