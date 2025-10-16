<?php

namespace Php\TlsCraft\Handshake\MessageParsers;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\Messages\KeyUpdate;
use Php\TlsCraft\Protocol\HandshakeType;

class KeyUpdateParser extends AbstractMessageParser
{
    public function parse(string $data): KeyUpdate
    {
        $payload = $this->parseHandshake($data, HandshakeType::KEY_UPDATE);

        if ($payload === '') {
            throw new CraftException('Invalid KeyUpdate message length');
        }

        return new KeyUpdate(ord($payload[0]) === 1);
    }
}
