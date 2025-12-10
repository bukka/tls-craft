<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Protocol\HandshakeType;

class FinishedMessage extends Message
{
    public function __construct(
        public readonly string $verifyData,
    ) {
        parent::__construct(HandshakeType::FINISHED);
    }
}
