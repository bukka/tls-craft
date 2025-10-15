<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Protocol\HandshakeType;

class Finished extends Message
{
    public function __construct(
        public readonly string $verifyData,
    ) {
        parent::__construct(HandshakeType::FINISHED);
    }

    public function encode(): string
    {
        return $this->verifyData;
    }
}
