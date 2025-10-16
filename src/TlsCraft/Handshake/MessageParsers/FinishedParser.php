<?php

namespace Php\TlsCraft\Handshake\MessageParsers;

use Php\TlsCraft\Handshake\Messages\Finished;
use Php\TlsCraft\Protocol\HandshakeType;

class FinishedParser extends AbstractMessageParser
{
    public function parse(string $data): Finished
    {
        $payload = $this->parseHandshake($data, HandshakeType::FINISHED);

        return new Finished($payload);
    }
}
