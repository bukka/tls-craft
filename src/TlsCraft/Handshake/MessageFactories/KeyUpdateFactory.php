<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\Messages\KeyUpdate;
use Php\TlsCraft\Protocol\HandshakeType;

class KeyUpdateFactory extends AbstractMessageFactory
{
    public function create(bool $requestUpdate): KeyUpdate
    {
        return new KeyUpdate($requestUpdate);
    }

    public function fromWire(string $data): KeyUpdate
    {
        $payload = $this->parseHandshake($data, HandshakeType::KEY_UPDATE);

        if ($payload === '') {
            throw new CraftException('Invalid KeyUpdate message length');
        }

        return new KeyUpdate(ord($payload[0]) === 1);
    }
}
