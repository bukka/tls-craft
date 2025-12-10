<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Crypto\CertificateChain;
use Php\TlsCraft\Protocol\HandshakeType;

class CertificateMessage extends Message
{
    public function __construct(
        public readonly string $certificateRequestContext,
        public readonly CertificateChain $certificateChain,
    ) {
        parent::__construct(HandshakeType::CERTIFICATE);
    }
}
