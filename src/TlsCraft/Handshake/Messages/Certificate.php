<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Protocol\HandshakeType;

class Certificate extends Message
{
    public function __construct(
        public readonly string $certificateRequestContext,
        public readonly array $certificateList, // array of certificate entries
    ) {
        parent::__construct(HandshakeType::CERTIFICATE);
    }
}
