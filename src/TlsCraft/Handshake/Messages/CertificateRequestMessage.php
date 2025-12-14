<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Protocol\HandshakeType;

class CertificateRequestMessage extends Message
{
    public function __construct(
        public readonly string $certificateRequestContext,
        array $extensions,
    ) {
        parent::__construct(HandshakeType::CERTIFICATE_REQUEST, $extensions);
    }
}
