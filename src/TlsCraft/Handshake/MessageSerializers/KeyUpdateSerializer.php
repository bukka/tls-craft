<?php

namespace Php\TlsCraft\Handshake\MessageSerializers;

use Php\TlsCraft\Handshake\Messages\KeyUpdate;

class KeyUpdateSerializer extends AbstractMessageSerializer
{
    public function serialize(KeyUpdate $message): string
    {
        return chr($message->requestUpdate ? 1 : 0);
    }
}
