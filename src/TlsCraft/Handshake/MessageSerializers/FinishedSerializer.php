<?php

namespace Php\TlsCraft\Handshake\MessageSerializers;

use Php\TlsCraft\Handshake\Messages\Finished;

class FinishedSerializer extends AbstractMessageSerializer
{
    public function serialize(Finished $message): string
    {
        return $message->verifyData;
    }
}
