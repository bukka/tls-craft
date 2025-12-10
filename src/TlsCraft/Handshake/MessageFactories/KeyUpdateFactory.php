<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Handshake\Messages\KeyUpdateMessage;

class KeyUpdateFactory extends AbstractMessageFactory
{
    public function create(bool $requestUpdate): KeyUpdateMessage
    {
        return new KeyUpdateMessage($requestUpdate);
    }
}
