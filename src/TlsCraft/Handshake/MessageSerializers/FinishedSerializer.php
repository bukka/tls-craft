<?php

namespace Php\TlsCraft\Handshake\MessageSerializers;

use Php\TlsCraft\Handshake\Messages\FinishedMessage;

class FinishedSerializer extends AbstractMessageSerializer
{
    public function serialize(FinishedMessage $message): string
    {
        return $message->verifyData;
    }
}
