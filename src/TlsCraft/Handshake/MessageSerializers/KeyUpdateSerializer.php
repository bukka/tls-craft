<?php

namespace Php\TlsCraft\Handshake\MessageSerializers;

use Php\TlsCraft\Handshake\Messages\KeyUpdateMessage;

class KeyUpdateSerializer extends AbstractMessageSerializer
{
    public function serialize(KeyUpdateMessage $message): string
    {
        return chr($message->requestUpdate ? 1 : 0);
    }
}
