<?php

namespace Php\TlsCraft\Messages\Factories;

use Php\TlsCraft\Messages\KeyUpdate;

class KeyUpdateFactory extends AbstractMessageFactory
{
    public function create(bool $requestUpdate): KeyUpdate
    {
        return new KeyUpdate($requestUpdate);
    }
}
