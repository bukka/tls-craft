<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Protocol\HandshakeType;

class KeyUpdate extends Message
{
    public function __construct(
        public readonly bool $requestUpdate,
    ) {
        parent::__construct(HandshakeType::KEY_UPDATE);
    }

    public function encode(): string
    {
        return chr($this->requestUpdate ? 1 : 0);
    }
}
