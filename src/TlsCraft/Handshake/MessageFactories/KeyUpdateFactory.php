<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Handshake\Messages\KeyUpdate;

class KeyUpdateFactory extends AbstractMessageFactory
{
    public function create(bool $requestUpdate): KeyUpdate
    {
        return new KeyUpdate($requestUpdate);
    }
}
