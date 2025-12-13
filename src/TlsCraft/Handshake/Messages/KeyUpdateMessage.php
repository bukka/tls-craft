<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Protocol\HandshakeType;

class KeyUpdateMessage extends Message
{
    public function __construct(
        public readonly bool $requestUpdate,
    ) {
        parent::__construct(HandshakeType::KEY_UPDATE);
    }
}
