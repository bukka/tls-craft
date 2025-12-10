<?php

namespace Php\TlsCraft\Handshake\MessageParsers;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\Messages\KeyUpdateMessage;
use Php\TlsCraft\Protocol\HandshakeType;

class KeyUpdateParser extends AbstractMessageParser
{
    public function parse(string $data): KeyUpdateMessage
    {
        $payload = $this->parseHandshake($data, HandshakeType::KEY_UPDATE);

        if ($payload === '') {
            throw new CraftException('Invalid KeyUpdateMessage message length');
        }

        return new KeyUpdateMessage(ord($payload[0]) === 1);
    }
}
