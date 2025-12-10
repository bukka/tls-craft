<?php

namespace Php\TlsCraft\Handshake\MessageParsers;

use Php\TlsCraft\Handshake\Messages\FinishedMessage;
use Php\TlsCraft\Protocol\HandshakeType;

class FinishedParser extends AbstractMessageParser
{
    public function parse(string $data): FinishedMessage
    {
        $payload = $this->parseHandshake($data, HandshakeType::FINISHED);

        return new FinishedMessage($payload);
    }
}
