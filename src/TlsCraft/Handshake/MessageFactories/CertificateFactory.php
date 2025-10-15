<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Handshake\Messages\Certificate;
use Php\TlsCraft\Protocol\HandshakeType;

class CertificateFactory extends AbstractMessageFactory
{
    public function create(array $certificateChain): Certificate
    {
        return new Certificate('', $certificateChain);
    }

    public function fromWire(string $data): Certificate
    {
        $payload = $this->parseHandshake($data, HandshakeType::CERTIFICATE);

        $offset = 0;

        // Certificate request context
        $contextLength = ord($payload[$offset]);
        ++$offset;
        $context = substr($payload, $offset, $contextLength);
        $offset += $contextLength;

        // Certificate list
        $listLength = unpack('N', "\x00".substr($payload, $offset, 3))[1];
        $offset += 3;

        $certificates = [];
        $endOffset = $offset + $listLength;

        while ($offset < $endOffset) {
            $certLength = unpack('N', "\x00".substr($payload, $offset, 3))[1];
            $offset += 3;

            $certificate = substr($payload, $offset, $certLength);
            $offset += $certLength;

            // Skip extensions
            $extLength = unpack('n', substr($payload, $offset, 2))[1];
            $offset += 2 + $extLength;

            $certificates[] = $certificate;
        }

        return new Certificate($context, $certificates);
    }
}
